#
#  Name:  ES-Search.ps
#
#  Written By:  Soren Frederiksen
#  Date:  4/7/2020
#
#  This script is built to perform a search in an ElasticSearch Database.
#
#  It takes in as a parameter the name of the index and the number of logs to print.
#
param(
	$size = 10,
    [string]$Index,
	[string]$output = "none",
	[string]$hostname = "10.0.0.200",
	$iterations=100,
	$debug=$true,
	[switch]$help
 )

function OutputData {
	param(
		[Parameter(Mandatory=$true)]$output,
		[Parameter(Mandatory=$true)]$result
	)
		
	if ($output -eq "none") {
		$result.hits.hits.fields.logmessage
	}
	else {
		$result.hits.hits.fields.logmessage >> $output
	}
}

if ($debug -and !$help) {write-host "
       ES-Search.ps
Extracting raw logs from server $hostname and Index $index
Extracting $size logs $iterations times

Ouput being sent to $output

"
}

if ($help) 
{
    write-host ' 
	
ES-Search 
   This script will connect to an ElasticSearch database and extract the raw logs from the specified index.
   
Parameters:

	-size  			Specifies the number of log messages extracted from ES database during each iteration. Must be less than or equal to 10000.

	-iterations		How many times the logs are extracted from the database (default=10)

	-Index  		The name of the index containing the logs
						LogRhythm format is  logs-<Year>-<Month>-<day>   (logs-2020-04-01)
			 
	-output			Name of output file

	-debug  		If set to $true addition informational messages will be printed.

	-hostname		Name or IP of ElasticSearch server

'
 	exit
}


$query = '{ 
  "from": 0, "size":'+$size+',
  "query":{
    "constant_score":{
        "filter":{
            "bool":{
                "must":[
                  {
                    "range":{
                      "insertedDate":{
                        "from":null,
                        "to":null,
                        "include_lower":true,
                        "include_upper":true,
                        "boost":1.0
                      }
                    }
                  },
                  {
                    "bool":{
                      "must":[
                        {
                          "bool":{
                            "disable_coord":false,
                            "adjust_pure_negative":true,
                            "boost":1.0
                          }
                        }
                      ],
                      "disable_coord":false,
                      "adjust_pure_negative":true,
                      "boost":1.0
                    }
                  }
                  ],
                  "disable_coord":false,
                  "adjust_pure_negative":true,
                  "boost":1.0
            }
        },
        "boost":1.0}},"_source":{"includes":[],"excludes":[]},"stored_fields":"*","sort":[{"normalDate":{"order":"asc"}}]}'


$Uri_scroll_10m = "http://"+$hostname+":9200/"+$index+"/_search?scroll=10m"
$Uri_scroll = "http://"+$hostname+":9200/_search/scroll"

$result = Invoke-RestMethod -Method Post -ContentType "application/json" -Body $query -Uri $Uri_scroll_10m

OutputData -output $output -result $result

$scroll_query = '{
   "scroll" : "1m",
   "scroll_id" : "'+$result._scroll_id+'"
}'

$total = $size

if ($debug)  {write-host "Count       Total Read" }

for ($i=1; $i -lt $iterations; $i++) {
#    $result2 = Invoke-RestMethod -Method Post -ContentType "application/json" -Body $scroll_query -Uri http://10.0.0.200:9200/_search/scroll
    $result2 = Invoke-RestMethod -Method Post -ContentType "application/json" -Body $scroll_query -Uri $Uri_scroll

    $total = $total + $size
    if ($debug)  {write-host "$i              $total" }
    if (!$result2.hits.hits) {
        break
    }

	OutputData -output $output -result $result2
} 


