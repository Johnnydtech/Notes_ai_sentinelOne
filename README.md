# Notes_ai_sentinelOne


## SentinelOneAPI Class

The SentinelOneAPI class is a custom class that is used to interact with the SentinelOne API. It takes the base_url and token as input parameters and initializes the class with the headers parameter that is required for making API requests.

## ThreatAnalyzer Class

The ThreatAnalyzer class is a custom class that is used to analyze the threat using the OpenAI GPT-3 model. It takes the openai_key as an input parameter and initializes the class with the api_key parameter that is required for making requests to the OpenAI API. It also has a method note_response that generates notes for the analyzed threat.

## ThreatAPI Class

The ThreatAPI class is the main class that uses the SentinelOneAPI and ThreatAnalyzer classes to retrieve information about threats from the SentinelOne API and analyze them using the OpenAI GPT-3 model. It has several methods for retrieving threat information, posting notes to threats, and deleting notes from threats. The run method is the main method that runs the script by checking for new threats and generating notes for them using the ThreatAnalyzer class.
