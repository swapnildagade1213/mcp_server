# meeting_mcp.py
from fastmcp import FastMCP,Context 
from exchangelib import  OAuth2Credentials, Configuration, Account, IMPERSONATION,Identity, Q
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from msal import ConfidentialClientApplication
BaseProtocol.HTTP_ADAPTER = NoVerifyHTTPAdapter()

mcp = FastMCP("My MCP Server")
@mcp.tool()
async def get_userUpcomingMeetings(ctx: Context, email: str, days : int, client_id : str, client_secret : str, tenant_id : str) -> str:
    """Get upcoming meetings of a user for the next specified days.

    Returns:
        Upcoming meetings of the user for the next specified days.
    """ 
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://outlook.office365.com/.default']

    # Target mailbox to impersonate 
    # Get access token using MSAL
    app = ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=scope)

    if "access_token" not in result:
        raise Exception("Could not obtain access token")
    
    credentials = OAuth2Credentials(client_id=client_id, client_secret=client_secret, tenant_id=tenant_id, identity=Identity(primary_smtp_address=email))
    config = Configuration(credentials=credentials, server='outlook.office365.com', auth_type='OAuth 2.0')
    account = Account(primary_smtp_address=email, config=config, autodiscover=False, access_type=IMPERSONATION)

    start = datetime.now(timezone.utc)
    end = start + timedelta(days=days)

    calendar_items = account.calendar.view(start=start, end=end).only('subject')
    meetings = []
    for item in calendar_items:
        meetings.append({
            "subject": item.subject
        })
    return json.dumps(meetings)

if __name__ == "__main__":
     mcp.run()
