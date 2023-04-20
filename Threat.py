import datetime
import requests
import json
from Main import SentinelOneAPI
from OpenAi import ThreatAnalyzer
import os

class ThreatAPI:
    def __init__(self, base_url, token, openai_key):
        self.S1 = SentinelOneAPI(base_url, token)
        self.TA = ThreatAnalyzer(openai_key)
        self.base_url = self.S1.base_url
        self.headers = self.S1.headers
        self.token = self.S1.token
        self.openai_key = self.TA.openai_key
        self.site_id = []
        self.last_run = None
        self.threat_list = []
        self.threat_id = []
        self.site_name = []
        
    def get_site(self):
        url="web/api/v2.1/sites"
        
        #Looking only for sites that are active
        params = {
            'limit': 1000,
            'state': 'active',
        }
        response = requests.get(self.base_url + url, params=params, headers=self.headers)
        site_info = response.json()['data']['sites']
        for n in range(len(site_info)):
            sites = site_info[n]
            site_name = sites['name']
            site_id = sites['id']
            self.site_id.append(site_id)
            self.site_name.append(site_name)

            print("Site name: \033[31m" + site_name + "\033[0m" + " and ID: \033[31m" + site_id + "\033[0m")


    def get_threat_details(self):
        url = "web/api/v2.1/threats"
        response = requests.get(self.base_url + url, headers=self.headers)

        if response.status_code == 200:
            threat_info = response.json()['data']
            if len(threat_info) == 0:
                print("no alerts today ")
            else:
                print(threat_info) 
        else:
            print("Error retrieving thre")

    def post(self, threat_id, notes):
        url="web/api/v2.1/threats/notes"
        data = {
            "data": {
                "text": notes
            },
            "filter": {
                "ids": [threat_id]
            }
        }

        # Send PUT request to update threat notes

        response = requests.post(self.base_url+url, headers=self.headers, data=json.dumps(data))
        
        #print(f"{response.json()} Comment added for alert")

    def delete(self, threat_id, note_id):
        url = f"web/api/v2.1/threats/{threat_id}/notes/{note_id}"

        response = requests.delete(self.base_url+url, headers=self.headers)

        #print(response.json())


    def get_recent_threat_id(self):
        url = "web/api/v2.1/threats"
        now = datetime.datetime.now(datetime.timezone.utc)

        # subtract one day
        one_day_ago = now - datetime.timedelta(days=2)

        # format as string in desired format
        formatted_date = one_day_ago.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        for n in self.site_id:
            params = {
                'limit' : 100,
                'noteExists' :'False',
                'siteIds': n,
                'createdAt__gte' : formatted_date,
                'resolved': 'False'
            }

            headers = {"Authorization": "ApiToken " + token, "Content-Type": "application/json"}
            # Send GET request to retrieve list of threats
            response = requests.get(self.base_url + url, params=params, headers=self.headers)

            if response.status_code == 200:
                threat_info = response.json()['data']
                if len(threat_info) == 0:
                    print("no alerts today ")
                else:
                    for n in range(len(threat_info)):
                        agentdetection_info=threat_info[n]
                        threat_id = agentdetection_info['threatInfo']['threatId']
                        self.threat_id.append(threat_id)
                        threat_dict = {
                            threat_id : {
                            'originating_process': agentdetection_info['threatInfo']['originatorProcess'],
                            'file_path': agentdetection_info['threatInfo']['filePath'],
                            'site_name': agentdetection_info['agentDetectionInfo']['siteName'],
                            'commandLine_arg': agentdetection_info['threatInfo']['maliciousProcessArguments'],
                            'hostname': agentdetection_info['agentRealtimeInfo']['agentComputerName'],
                            'identified_at' : datetime.datetime.strptime(agentdetection_info['threatInfo']['identifiedAt'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')
                            }
                        }
                        self.threat_list.append(threat_dict)
                        # Print the values for each threat

                        #print(f"{self.threat_list}")

            else:
                print("Error retrieving threat")

    def run(self):
        # Get the most recent threat ID
        self.get_site()
        self.get_recent_threat_id()

        print(len(self.threat_id))
        for n in range(len(self.threat_id)):
            threat_id = self.threat_id[n]
            threat_info_list = self.threat_list[n][threat_id]
            print(threat_info_list)
            # Check if there are any new threats since the last run
            # Your code here
            print("New threat detected...")
            # Analyze the threat and make notes
            self.TA.note_response(threat_info_list['file_path'], threat_info_list['originating_process'], threat_info_list['commandLine_arg'])
            # Add notes to the threat
            print(self.TA.notes)
            self.post(threat_id,self.TA.notes)
            
            #print("Comments added for the alerts")
            
            webhook_url = 'https://appriver3651011841.webhook.office.com/webhookb2/3531645f-e6ca-4980-8f61-4a123378bcad@573857c8-1ada-485a-9226-0c05fca4dabc/IncomingWebhook/e1ccd29ad09b438b8e1b79eb7ff8b9b1/0fadc43d-d929-49a7-8746-4403bc81cb1c'
            headers = {'Content-type': 'application/json'}
            payload = {'text': f'New threat detected for client {threat_info_list['site_name']}: {self.TA.notes}'}
            response = requests.post(webhook_url, json=payload, headers=headers)
            if response.status_code == 200:
                print('Webhook alert sent successfully.')
        


base_url = os.environ.get('BASE_URL')
openai_key = os.environ.get('OPENAI_KEY')
token = os.environ.get('TOKEN')

Threat = ThreatAPI(base_url, token, openai_key)

Threat.run()

