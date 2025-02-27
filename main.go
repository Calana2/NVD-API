package main

import (
	"flag"
	"fmt"
	nvd "main/CVE-API-client"
	"main/utils"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	helpFlag := flag.Bool("help", false, "")
	flag.BoolVar(helpFlag, "h", false, "")
	// Search flags
	cveIdFlag := flag.String("cve-id", "", "Returns a specific vulnerability identified by its unique Common Vulnerabilities and Exposures identifier")
	// Verbose flags
	verboseFlag := flag.Bool("verbose", false, "Show references")
	flag.BoolVar(verboseFlag, "v", false, "")

	flag.Parse()
	//fmt.Println("#FLAG", flag.NFlag())
	if flag.NFlag() == 0 || *helpFlag || (flag.NFlag() == 1 && *verboseFlag) {
		fmt.Println("NVD API Client\n")
		fmt.Println("Usage: program [options]\n")
		fmt.Println("Options")
		fmt.Println("-h, --help  Print help")
		fmt.Println("--cve-id Returns a specific vulnerability identified by its unique Common Vulnerabilities and Exposures identifier")
		fmt.Println("-v, --verbose Show references")
		os.Exit(0)
	}

	err := godotenv.Load()
	if err != nil {
		// No problem
	}
	apiKey := os.Getenv("API_KEY")

	client := nvd.New(apiKey)
	var results *nvd.CVESearch
	if *cveIdFlag != "" {
		results, err = client.CVESearch(fmt.Sprintf("cveId=%s", *cveIdFlag))
		if err != nil {
			fmt.Println("Error with the query: ", err)
			os.Exit(1)
		}
	}

	var identifier string
	var status string
	var quickInfo []string
  var description string
  var cisaData *nvd.CISA_KEVC;
	var references []string
	for _, cve := range results.Vulnerabilities {
		// Collect data
		identifier = cve.CVE.ID
		status = cve.CVE.VulnStatus
		quickInfo = append(quickInfo, fmt.Sprintf("CVE Dictionary Entry: %s", cve.CVE.ID))
		publishedDate, err := time.Parse("2006-01-02T15:04:05.000", cve.CVE.Published)
		if err != nil {
			quickInfo = append(quickInfo, fmt.Sprintf("NVD Published Date: %s", cve.CVE.Published))
		} else {
			quickInfo = append(quickInfo, fmt.Sprintf("NVD Published Date: %s\n", publishedDate.Format("2006-01-02 15:04:05")))
		}
		lastModifiedDate, err := time.Parse("2006-01-02T15:04:05.000", cve.CVE.LastModified)
		if err != nil {
			quickInfo = append(quickInfo, fmt.Sprintf("NVD Last Modified Date: %s\n", cve.CVE.LastModified))
		} else {
			quickInfo = append(quickInfo, fmt.Sprintf("NVD Last Modified Date: %s\n", lastModifiedDate.Format("2006-01-02 15:04:05")))
		}
		quickInfo = append(quickInfo, fmt.Sprintf("Source: %s\n\n", cve.CVE.SourceIdentifier))
    description = cve.CVE.Descriptions[0].Value
    if(cve.CVE.CisaVulnerabilityName != "") {
     cisaData = &nvd.CISA_KEVC{VulnerabilityName: cve.CVE.CisaVulnerabilityName,
                              DateAdded: cve.CVE.CisaExploitAdd,
                              DueDate:cve.CVE.CisaActionDue,
                              RequiredAction: cve.CVE.CisaRequiredAction}
    }
		for _, ref := range cve.CVE.References {
			s := ref.URL + " ("
			for _, reftag := range ref.Tags {
				s += reftag + ", "
			}
			s = s[:len(s)-2] // erase trailing ,
			s += ")"
			references = append(references, s)
		}
	}

	// Print output
  // Details
	fmt.Printf("\n%s Detail:\n", identifier)
	fmt.Println("+--------------------------------------------------------------------------+")
	fmt.Printf("| %-73s|\n", status)
	fmt.Printf("|%s|\n", strings.Repeat("-",74))
	statusDesc := utils.DivideString(nvd.NVDStatuses[status], 73)
	for _, line := range statusDesc {
		fmt.Printf("| %-73s|\n", line)
	}
	fmt.Println("+--------------------------------------------------------------------------+")
  // Quick info
	fmt.Printf("\nQuick Info:\n")
	fmt.Println("+--------------------------------------------------------------------------+")
	for _, text := range quickInfo {
		fmt.Printf("| %-73s|\n", strings.TrimSpace(text))
	}
	fmt.Println("+--------------------------------------------------------------------------+")
  // Description
  fmt.Printf("\nDescription:\n")
  fmt.Printf("-------------\n")
  fmt.Printf("%s\n",description)
  // Cibersecurity and Infrastructure Agency (CISA) Known Exploited Vulnerabilities Catalog
  if cisaData != nil {
    fmt.Printf("\nCISA's Known Exploited Vulnerabilities Catalog:\n")
    fmt.Printf("------------------------------------------------\n")
   fmt.Printf("Vulnerability Name: %s\n",cisaData.VulnerabilityName)
   fmt.Printf("Date Added: %s\n",cisaData.DateAdded)
   fmt.Printf("Due Date: %s\n",cisaData.DueDate)
   fmt.Printf("Required action: %s\n",cisaData.RequiredAction)
  }
  // References
	if *verboseFlag {
		fmt.Printf("\nReferences:\n")
		if len(references) > 0 {
			for _, text := range references {
				fmt.Printf("%s\n", text)
			}
		} else {
			fmt.Printf("No references found.")
		}
	}
}
