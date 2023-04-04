import requests
import json
import openai
import datetime

class ThreatAnalyzer:
    def __init__(self, openai_key):
        self.openai_key = openai_key
        self.notes = None

    def note_response(self, file_path, originating_process, commandLine_arg):
        openai.api_key = self.openai_key
       # Note: you need to be using OpenAI Python v0.27.0 for the code below to work
        response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
                {"role": "system", "content": "You are an AI that analyzes files for malicious content using multiple Varaibles from the user."},
                {"role": "user", "content": f"analyze the alert using the {file_path}, {originating_process}, and {commandLine_arg} if the data is insufficient, just analyze the filepath and share what you find."}    
            ]
        )
        self.notes = response['choices'][0]['message']['content']
        