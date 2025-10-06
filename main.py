import asyncio

async def main():
    from fastmcp import FastMCP
    mcp = FastMCP(name="My Server")

    @mcp.tool
    def hello(name: str) -> str:
        return f"Hello, {name}!"

    await mcp.run_async()

if __name__ == "__main__":
    asyncio.run(main())
