import boto3
from botocore.exceptions import ClientError

session = boto3.Session(
    profile_name="echoshield",
    region_name="us-east-1"
)
client = session.client("bedrock-runtime")

try:
    response = client.converse(
        modelId="amazon.nova-micro-v1:0",
        messages=[
            {
                "role": "user",
                "content": [{"text": "Reply with OK only."}]
            }
        ],
        inferenceConfig={"maxTokens": 10}
    )
    print("SUCCESS:", response["output"]["message"]["content"][0]["text"])
except ClientError as e:
    print("AWS ERROR CODE:", e.response["Error"].get("Code"))
    print("AWS ERROR MESSAGE:", e.response["Error"].get("Message"))
except Exception as e:
    print("LOCAL ERROR:", type(e).__name__, str(e))
