



def fetch_graphToken(saltdata : str, keydata : str)-> str:
    """
    Fetch Graph Token
    
    Args:
        saltdata (str): saltdata
        keydata (str): keydata      
        
    Returns:
        str: JWTToken
    """
    client_id = "Z0FBQUFBQm83Y3JUUUFTd1JUN3A2YndQa2JCdHZadDhlUV8zcmZPYWc2ZnFkSlNEWlRqc1hjeEVpSE0wZzNPTlVUU0h2Uk0xMzNjaDdIN2EzR3M0Rm5uM0ZEUVU0NTYwc2xwUUR1OVBqQ2o0UHFfTFdONjdNOEFDczRwVjFNakpnTnNWaHRjNlVPbGQ="
    client_secret = "[Credentials]"
    tenant_id = "Z0FBQUFBQm83Y3JUelJ5d1pFTDE0c3MzWWgyd0FpXzNoLS1nZE45Q0psREpDYmI5SFlNSm1zd0dzdUFDWERhdndDYWRYdTBjMkRLa0NKQU91NVYxU2lYZ1VLaDg3NTJDekhWQzNiY0ZjRHpGbUZ2TktXZmdXNWpJUkJJX2IwbXI3a3A2U1I5LVdoUDA="
    client_id = get_DecryptedText(client_id,saltdata,keydata)
    client_secret = get_DecryptedText(client_secret,saltdata,keydata)
    tenant_id = get_DecryptedText(tenant_id,saltdata,keydata)
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://graph.microsoft.com/.default']
    app = ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )
    token_response = app.acquire_token_for_client(scopes=scope)
    if 'access_token' in token_response:
        return f"{token_response['access_token']}"
    else:
        return f"Token not reterived"

@mcp.tool() 
def get_Countrycode()-> str:
    """
    Fetch Country code
    
    Args: None
        
    Returns:
        str: Country code
    """
    return "#INDIA123"

@mcp.tool()
async def get_userUpcomingMeetings(email: str, saltdata : str, keydata : str ) -> str:
    """Get upcoming meetings of a user for the next specified days.


    Returns:
        Upcoming meetings of the user for the next specified days.
    """ 


    client_id = "Z0FBQUFBQnBBZExWcGxja25NVk11QjdTbWVIS0VrTFRxSms2RTM5UTA2ell5ZGp2UHdTNXlvbTJ4MGx6NkZ4aVNJSXF4bm9ZRDVReXBkQ1B2dFpqVHBJNjlGaWZhYWFhdm8zRzk0aWdrZl82MnVIaTVPMU5JMlJnN1gzLWhjbkpJTlhQam9vc04zeHU="
    client_secret = "[Credentials]"
    tenant_id = "Z0FBQUFBQm83Y3JUelJ5d1pFTDE0c3MzWWgyd0FpXzNoLS1nZE45Q0psREpDYmI5SFlNSm1zd0dzdUFDWERhdndDYWRYdTBjMkRLa0NKQU91NVYxU2lYZ1VLaDg3NTJDekhWQzNiY0ZjRHpGbUZ2TktXZmdXNWpJUkJJX2IwbXI3a3A2U1I5LVdoUDA="
    client_id = get_DecryptedText(client_id,saltdata,keydata)
    client_secret = get_DecryptedText(client_secret,saltdata,keydata)
    tenant_id = get_DecryptedText(tenant_id,saltdata,keydata)
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://outlook.office365.com/.default']


    # Target mailbox to impersonate 
    # Get access token using MSAL
    app = ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_secret,
    )
    token_response = app.acquire_token_for_client(scopes=scope)
    if 'access_token' not in token_response:
        return f"Token not reterived"
    
    credentials = OAuth2Credentials(client_id=client_id, client_secret=client_secret, tenant_id=tenant_id, identity=Identity(primary_smtp_address=email))
    config = Configuration(credentials=credentials, server='outlook.office365.com', auth_type='OAuth 2.0')
    account = Account(primary_smtp_address=email, config=config, autodiscover=False, access_type=IMPERSONATION)


    start = datetime.now(timezone.utc)
    end = start + timedelta(days=2)


    calendar_items = account.calendar.view(start=start, end=end).only('subject')
    meetings = []
    for item in calendar_items:
        meetings.append({
            "subject": item.subject
        })
    return json.dumps(meetings)


@mcp.tool()
def get_employeePresence(employeeId : str, saltdata : str, keydata : str)-> Dict[str, Any]:
    """
    Fetch Employee Info
    
    Args:
        employeeId (str): employeeId
        saltdata (str): saltdata
        keydata (str): keydata
        
    Returns:
        str: Employee Info
