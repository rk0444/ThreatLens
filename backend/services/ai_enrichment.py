import os
import json
import requests
import re
from typing import List
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

def extract_actors_from_description(description: str) -> List[str]:
    """Uses Groq's fast Llama 3 to identify threat actors from a CVE description."""
    if not GROQ_API_KEY or GROQ_API_KEY == "your_groq_key_here":
        return ["Unknown Actor"]
        
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    prompt = f"""
    Analyze the following CVE vulnerability description. 
    Identify 1 or 2 specific Advanced Persistent Threats (APTs), ransomware gangs, or hacker groups (e.g., Lazarus Group, LockBit, APT29) that are realistically known to exploit this type of vulnerability, or use this technology.
    If it's a Microsoft vulnerability, you might mention Russian or Chinese state-sponsored groups. If it's a Linux/Web vulnerability, you might mention botnets or ransomware operators.
    Return ONLY a raw JSON array of strings containing the names of the groups. Do not include markdown or other text.
    Description: {description}
    """
    
    data = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 50
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=5)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        
        match = re.search(r'\[.*?\]', content, re.DOTALL)
        if match:
            actors = json.loads(match.group(0))
            if isinstance(actors, list) and len(actors) > 0:
                return [str(a) for a in actors]
    except Exception as e:
        print(f"Failed to extract actors: {e}")
        
    return ["Unknown Actor"]
