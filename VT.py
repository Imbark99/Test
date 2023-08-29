import streamlit as st
import pandas as pd
import requests

API_KEY = 'b66edaf4b66520d9a8d17bc674fde9821c9327c04c1e99a82b8186ac486c2b02'

def get_virustotal_data(item):
    headers = {
        "x-apikey": API_KEY
    }
    # Function to convert country code to country name
    def get_country_name(country_code):
        try:
            return pycountry.countries.get(alpha_2=country_code).name
        except AttributeError:
            return country_code  # If the conversion fails, return the code itself

    # Determine if it's an IP, Hash, URL, or Domain
    if len(item.split('.')) == 4:  # Assuming it's an IP
        endpoint = f'https://www.virustotal.com/api/v3/ip_addresses/{item}'
    elif len(item) == 32 or len(item) == 40 or len(item) == 64:  # Assuming it's a hash (MD5, SHA1, SHA256)
        endpoint = f'https://www.virustotal.com/api/v3/files/{item}'
    elif '://' in item:  # Assuming it's a URL
        endpoint = f'https://www.virustotal.com/api/v3/urls/{item}'
    else:  # Assuming it's a Domain
        endpoint = f'https://www.virustotal.com/api/v3/domains/{item}'

    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        result = {
            "item": item,
            "score": f"{data['data']['attributes']['last_analysis_stats']['malicious']}/{data['data']['attributes']['last_analysis_stats']['harmless']}",
            "reputation": data['data']['attributes'].get('reputation', 'N/A'),
        }
        
        if endpoint.endswith(f'ip_addresses/{item}'):
            result.update({
                "type": "IP",
                "country": data['data']['attributes'].get('country', 'N/A'),
                "details": ", ".join([domain['id'] for domain in data.get('data', {}).get('relationships', {}).get('resolutions', {}).get('data', [])])
            })
        else:
            result.update({
                "type": "Hash" if (len(item) in [32, 40, 64]) else ("URL" if '://' in item else "Domain"),
                "details": data['data']['id']
            })
            
        return result
    else:
        return {"item": item, "error": response.text}
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        result = {
            "item": item,
            "score": f"{data['data']['attributes']['last_analysis_stats']['malicious']}/{data['data']['attributes']['last_analysis_stats']['harmless']}",
            "reputation": data['data']['attributes'].get('reputation', 'N/A'),
        }
        
        if endpoint.endswith(f'ip_addresses/{item}'):
            country_code = data['data']['attributes'].get('country', 'N/A')
            result.update({
                "type": "IP",
                "country": get_country_name(country_code)  # Use our conversion function here
            })
        else:
            result.update({
                "type": "Hash" if (len(item) in [32, 40, 64]) else ("URL" if '://' in item else "Domain"),
            })
            
        return result
    else:
        return {"item": item, "error": response.text}
        
def main():
    st.title("VirusTotal Bulk Lookup")

    uploaded_file = st.file_uploader("Upload CSV or TXT file", type=['csv', 'txt'])
    user_input = st.text_area("Paste your hashes/IPs/URLs/Domains here (newline separated)")
    submit_button = st.button("Submit")

    if submit_button:
        if uploaded_file:
            if uploaded_file.type == "text/csv":
                data = pd.read_csv(uploaded_file)
            else:
                data = pd.DataFrame({'item': [line.strip().decode('utf-8') for line in uploaded_file.readlines()]})

            results = [get_virustotal_data(item) for item in data['item']]
            df_results = pd.DataFrame(results)

            st.table(df_results)

            csv = df_results.to_csv(index=False)
            st.download_button("Download CSV", csv, "output.csv")

        elif user_input:
            items = user_input.split('\n')
            results = [get_virustotal_data(item.strip()) for item in items]
            df_results = pd.DataFrame(results)
            
            st.table(df_results)
            
            csv = df_results.to_csv(index=False)
            st.download_button("Download CSV", csv, "output.csv")

if __name__ == "__main__":
    main()
