import requests
import json
import openai
import datetime

class SentinelOneAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.headers = {"Authorization": "ApiToken " + self.token, "Content-Type": "application/json"}
        
