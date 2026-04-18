import whois
from datetime import datetime

def get_domain_age(domain):
    """
    Fetches WHOIS information for a given domain and calculates its age in days.
    Returns a tuple: (creation_date, age_in_days)
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if not creation_date:
            return None, None
            
        # Some registrars return a list of dates; we take the first one
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        # Calculate age in days if we have a valid datetime object
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_in_days = (datetime.now() - creation_date).days
            return creation_date, age_in_days
        else:
            return creation_date, None
            
    except Exception as e:
        print(f"Error fetching WHOIS for {domain}: {e}")
        return None, None

if __name__ == "__main__":
    import sys
    
    # Check if user provided custom domains via command line arguments
    test_domains = sys.argv[1:] if len(sys.argv) > 1 else ["google.com", "github.com", "example.com"]
    
    print("Testing WHOIS Domain Age Extraction (No API Key Required)...\n")
    
    for domain in test_domains:
        date, age = get_domain_age(domain)
        if age is not None:
            print(f"[✅] Domain: {domain:<20} | Created: {date.strftime('%Y-%m-%d'):<12} | Age: {age} days")
        else:
            print(f"[❌] Domain: {domain:<20} | Could not determine age or WHOIS data blocked.")
