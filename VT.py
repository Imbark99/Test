import streamlit as st
import pandas as pd
import requests

API_KEY = 'b66edaf4b66520d9a8d17bc674fde9821c9327c04c1e99a82b8186ac486c2b02'

def get_virustotal_data(item):
    headers = {
        "x-apikey": API_KEY
    }
    
    if len(item.split('.')) == 4:  # Assuming it's an IP
        response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{item}', headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "item": item,
                "score": f"{data['data']['attributes']['last_analysis_stats']['malicious']}/{data['data']['attributes']['last_analysis_stats']['harmless']}",
                "reputation": data['data']['attributes']['reputation'],
                "country": data.get('data', {}).get('attributes', {}).get('country', 'N/A'),
                "domain_name": ", ".join([domain['id'] for domain in data.get('data', {}).get('relationships', {}).get('resolutions', {}).get('data', [])])
            }
        else:
            return {"item": item, "error": response.text}

    return {"item": item, "error": "Unrecognized format"}

def main():
    st.title("VirusTotal Bulk Lookup")

    uploaded_file = st.file_uploader("Upload CSV or TXT file", type=['csv', 'txt'])

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

    else:
        user_input = st.text_area("Paste your hashes/IPs here (newline separated)")
        if user_input:
            items = user_input.split('\n')
            results = [get_virustotal_data(item.strip()) for item in items]
            df_results = pd.DataFrame(results)
            
            st.table(df_results)
            
            csv = df_results.to_csv(index=False)
            st.download_button("Download CSV", csv, "output.csv")

if __name__ == "__main__":
    main()
