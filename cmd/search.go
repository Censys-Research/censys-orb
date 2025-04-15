package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/censys-research/censys-orb/pkg/greynoise"
	censys_sdk "github.com/censys/censys-sdk-go-internal"
	comps "github.com/censys/censys-sdk-go-internal/models/components"
	copers "github.com/censys/censys-sdk-go-internal/models/operations"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	pageSize    int64
	numPages    int
	matchesOnly bool
)

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search Censys and check results against GreyNoise",
	Args:  cobra.ExactArgs(1),
	RunE:  runSearch,
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	searchStr := args[0]

	// Get Censys credentials from environment
	token := os.Getenv("CENSYS_PLATFORM_TOKEN")
	orgID := os.Getenv("CENSYS_PLATFORM_ORGID")
	if token == "" || orgID == "" {
		return fmt.Errorf("CENSYS_PLATFORM_TOKEN and CENSYS_PLATFORM_ORGID environment variables must be set")
	}

	// Initialize Censys client
	censysClient := censys_sdk.New(
		censys_sdk.WithSecurity(token),
		censys_sdk.WithOrganizationID(orgID),
	)

	// Set up search request
	search := comps.SearchQueryInputBody{
		Fields:    []string{"host.ip"}, // We only need the IP field
		PageSize:  &pageSize,
		PageToken: nil,
		Query:     searchStr,
	}

	req := copers.V3GlobaldataSearchQueryRequest{
		SearchQueryInputBody: search,
	}

	// Collect all IPs
	var allIPs []string
	page := 0

	for {
		page++
		logrus.Infof("Fetching page %d of Censys results", page)

		res, err := censysClient.GlobalData.Search(ctx, req)
		if err != nil {
			return fmt.Errorf("censys search failed: %w", err)
		}

		result := res.GetResponseEnvelopeSearchQueryResponse().GetResult()
		hits := result.GetHits()

		// Extract IPs from the hits
		for _, hit := range hits {
			if hit.GetHostV1() == nil {
				continue
			}
			resource := hit.GetHostV1().GetResource()
			ipPtr := resource.GetIP()
			if ipPtr != nil {
				allIPs = append(allIPs, *ipPtr)
			}
		}

		next := result.GetNextPageToken()
		req.SearchQueryInputBody.PageToken = &next

		if numPages > 0 && page >= numPages {
			break
		}

		if next == "" {
			break
		}
	}

	if len(allIPs) == 0 {
		logrus.Info("No IPs found in Censys search")
		return nil
	}

	logrus.Infof("Found %d IPs, checking against GreyNoise", len(allIPs))

	// Get API key from flag or environment
	apiKey := os.Getenv("GREYNOISE_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("GreyNoise API key must be provided via GREYNOISE_API_KEY environment variable")
	}

	// Create GreyNoise client
	gnClient := greynoise.NewClient(
		apiKey,
		greynoise.WithUserAgent("censys-greynoise-cli"),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Do bulk quick lookup for all IPs
	quickResults, err := gnClient.BulkQuickLookup(ctx, allIPs)
	if err != nil {
		return fmt.Errorf("bulk quick lookup failed: %w", err)
	}

	// Process results
	var noiseIPs []string
	var riotIPs []string
	resultMap := make(map[string]*greynoise.QuickResponse)

	for _, result := range quickResults {
		resultMap[result.IP] = &result
		if result.Noise {
			noiseIPs = append(noiseIPs, result.IP)
		}
		if result.Riot {
			riotIPs = append(riotIPs, result.IP)
		}
	}

	// Get context for noise IPs
	contextResults := make(map[string]*greynoise.ContextResponse)
	for _, ip := range noiseIPs {
		contextResp, err := gnClient.ContextLookup(ctx, ip)
		if err != nil {
			logrus.WithError(err).Errorf("context lookup failed for IP %s", ip)
			continue
		}
		contextResults[ip] = contextResp
	}

	// Get riot info for riot IPs
	riotResults := make(map[string]*greynoise.RiotResponse)
	for _, ip := range riotIPs {
		riotResp, err := gnClient.RiotLookup(ctx, ip)
		if err != nil {
			logrus.WithError(err).Errorf("riot lookup failed for IP %s", ip)
			continue
		}
		riotResults[ip] = riotResp
	}

	// Print results based on format
	switch outputFormat {
	case "json":
		printJSONResults(allIPs, resultMap, contextResults, riotResults)
	case "table":
		printTableResults(allIPs, resultMap, contextResults, riotResults)
	}

	return nil
}

func printJSONResults(ips []string, quick map[string]*greynoise.QuickResponse, context map[string]*greynoise.ContextResponse, riot map[string]*greynoise.RiotResponse) {
	type combinedResult struct {
		IP      string                     `json:"ip"`
		Quick   *greynoise.QuickResponse   `json:"quick"`
		Context *greynoise.ContextResponse `json:"context,omitempty"`
		Riot    *greynoise.RiotResponse    `json:"riot,omitempty"`
	}

	results := make([]combinedResult, 0)
	for _, ip := range ips {
		quickResult := quick[ip]
		if quickResult == nil {
			continue
		}

		if matchesOnly && !quickResult.Noise && !quickResult.Riot {
			continue
		}

		result := combinedResult{
			IP:      ip,
			Quick:   quickResult,
			Context: context[ip],
			Riot:    riot[ip],
		}
		results = append(results, result)
	}

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal results to JSON")
		return
	}
	fmt.Println(string(jsonBytes))
}

func printTableResults(ips []string, quick map[string]*greynoise.QuickResponse, context map[string]*greynoise.ContextResponse, riot map[string]*greynoise.RiotResponse) {
	for i, ip := range ips {
		quickResult := quick[ip]
		if quickResult == nil {
			continue
		}

		if matchesOnly && !quickResult.Noise && !quickResult.Riot {
			continue
		}

		if i > 0 {
			fmt.Println()
		}

		fmt.Printf("IP: %s\n", ip)
		fmt.Printf("Quick Lookup:\n")
		fmt.Printf("  Noise: %v\n", quickResult.Noise)
		fmt.Printf("  Riot: %v\n", quickResult.Riot)
		fmt.Printf("  Code: %s\n", quickResult.Code)

		if contextResult := context[ip]; contextResult != nil {
			fmt.Printf("\nContext Information:\n")
			printContextDetails(contextResult)
		}

		if riotResult := riot[ip]; riotResult != nil {
			fmt.Printf("\nRIOT Information:\n")
			printRiotDetails(riotResult)
		}
	}
}

func printContextDetails(resp *greynoise.ContextResponse) {
	printContextResponse(resp)
}

func printRiotDetails(resp *greynoise.RiotResponse) {
	printRiotResponse(resp)
}

func printRiotResponse(resp *greynoise.RiotResponse) {
	fmt.Printf("IP: %s\n", resp.IP)
	fmt.Printf("  Category: %s\n", resp.Category)
	fmt.Printf("  Name: %s\n", resp.Name)
	fmt.Printf("  Description: %s\n", resp.Description)
	if resp.Explanation != "" {
		fmt.Printf("  Explanation: %s\n", resp.Explanation)
	}
	fmt.Printf("  Last Updated: %s\n", resp.LastUpdated)
	fmt.Printf("  Trust Level: %v\n", resp.Trust)
}

func printContextResponse(resp *greynoise.ContextResponse) {
	fmt.Printf("IP: %s\n", resp.IP)
	fmt.Printf("  First Seen: %s\n", resp.FirstSeen)
	fmt.Printf("  Last Seen: %s\n", resp.LastSeen)
	fmt.Printf("  Classification: %s\n", resp.Classification)
	fmt.Printf("  Actor: %s\n", resp.Actor)
	fmt.Printf("  Spoofable: %v\n", resp.Spoofable)
	fmt.Printf("  Bot: %v\n", resp.Bot)
	fmt.Printf("  VPN: %v\n", resp.VPN)
	if resp.VPNService != "" {
		fmt.Printf("  VPN Service: %s\n", resp.VPNService)
	}

	if len(resp.CVE) > 0 {
		fmt.Printf("  CVEs:\n")
		for _, cve := range resp.CVE {
			fmt.Printf("    - %s\n", cve)
		}
	}

	if len(resp.Tags) > 0 {
		fmt.Printf("  Tags:\n")
		for _, tag := range resp.Tags {
			fmt.Printf("    - %s\n", tag)
		}
	}

	fmt.Printf("  Metadata:\n")
	meta := resp.Metadata
	fmt.Printf("    Location: %s, %s, %s\n", meta.City, meta.Region, meta.Country)
	fmt.Printf("    Organization: %s (%s)\n", meta.Organization, meta.ASN)
	fmt.Printf("    Category: %s\n", meta.Category)
	fmt.Printf("    Operating System: %s\n", meta.OS)
	if meta.Tor {
		fmt.Printf("    TOR Exit Node: Yes\n")
	}
	fmt.Printf("    Sensor Stats: %d hits across %d sensors\n", meta.SensorHits, meta.SensorCount)

	if len(meta.DestinationCountries) > 0 {
		fmt.Printf("    Target Countries: %s\n", strings.Join(meta.DestinationCountries[:min(5, len(meta.DestinationCountries))], ", "))
		if len(meta.DestinationCountries) > 5 {
			fmt.Printf("      ... and %d more\n", len(meta.DestinationCountries)-5)
		}
	}

	fmt.Printf("  Activity:\n")
	protocols := make(map[string][]int)
	for _, scan := range resp.RawData.Scan {
		protocols[scan.Protocol] = append(protocols[scan.Protocol], scan.Port)
	}
	for proto, ports := range protocols {
		sort.Ints(ports)
		if len(ports) > 5 {
			fmt.Printf("    %s ports (%d): %v ...\n", proto, len(ports), ports[:5])
		} else {
			fmt.Printf("    %s ports (%d): %v\n", proto, len(ports), ports)
		}
	}

	if len(resp.RawData.JA3) > 0 {
		fmt.Printf("    JA3 Fingerprints: %d unique signatures\n", len(resp.RawData.JA3))
	}
	if len(resp.RawData.Hassh) > 0 {
		fmt.Printf("    HASSH Fingerprints: %d unique signatures\n", len(resp.RawData.Hassh))
	}
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().Int64VarP(&pageSize, "per-page", "p", 100, "Number of results per page from Censys")
	searchCmd.Flags().IntVarP(&numPages, "num-pages", "n", -1, "Number of pages to fetch from Censys")
	searchCmd.Flags().BoolVar(&matchesOnly, "matches-only", true, "Only show IPs that have noise or riot data")
}
