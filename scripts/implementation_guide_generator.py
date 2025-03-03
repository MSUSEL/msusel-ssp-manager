import json
import os
from openai import OpenAI
import time
from dotenv import load_dotenv

load_dotenv()  # Load API key from .env file
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generate_implementation_guides(controls_data):
    """Use AI to generate brief implementation guides for controls"""
    implementation_guides = {}
    
    for control in controls_data:
        control_id = control["Control_ID"]
        control_name = control["Control_Name"]
        
        # Skip if already processed
        if control_id in implementation_guides:
            continue
            
        prompt = f"""
        Provide a brief (50-75 words) practical implementation guide for the NIST SP 800-53 control:
        {control_id}: {control_name}
        
        Focus on concrete steps, not theory. Format as a bulleted list of 3-4 key implementation steps.
        """
        
        try:
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "system", "content": "You are a cybersecurity expert."}, 
                          {"role": "user", "content": prompt}],
                max_tokens=150
            )
            
            implementation_guides[control_id] = response.choices[0].message.content.strip()
            print(f"Generated guide for {control_id}")
            
            # Rate limiting
            time.sleep(1)
            
        except Exception as e:
            print(f"Error generating guide for {control_id}: {e}")
    
    return implementation_guides

def main():
    # Load existing control data
    with open('../flask/react-app/src/data/mappings.json', 'r') as f:
        controls_data = json.load(f)
    
    # Generate implementation guides
    implementation_guides = generate_implementation_guides(controls_data)
    
    # Save to JSON
    with open('../flask/react-app/src/data/implementation_guides.json', 'w') as f:
        json.dump(implementation_guides, f, indent=2)

if __name__ == "__main__":
    main()
