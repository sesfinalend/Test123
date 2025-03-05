# Generated from trimmed zed.proto
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'zed.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tzed.proto\x12\x0czed.messages\"&\n\x06PeerId\x12\x10\n\x08owner_id\x18\x01 \x01(\r\x12\n\n\x02id\x18\x02 \x01(\r\"\xe2\x05\n\x08\x45nvelope\x12\n\n\x02id\x18\x01 \x01(\r\x12\x1a\n\rresponding_to\x18\x02 \x01(\rH\x01\x88\x01\x01\x12\x35\n\x12original_sender_id\x18\x03 \x01(\x0b\x32\x14.zed.messages.PeerIdH\x02\x88\x01\x01\x12\x14\n\x06\x61\x63k_id\x18\x8a\x02 \x01(\rH\x03\x88\x01\x01\x12$\n\x05hello\x18\x04 \x01(\x0b\x32\x13.zed.messages.HelloH\x00\x12 \n\x03\x61\x63k\x18\x05 \x01(\x0b\x32\x11.zed.messages.AckH\x00\x12$\n\x05\x65rror\x18\x06 \x01(\x0b\x32\x13.zed.messages.ErrorH\x00\x12\"\n\x04ping\x18\x07 \x01(\x0b\x32\x12.zed.messages.PingH\x00\x12\x46\n\x17\x61\x63\x63\x65pt_terms_of_service\x18\xef\x01 \x01(\x0b\x32".zed.messages.AcceptTermsOfServiceH\x00\x12W\n accept_terms_of_service_response\x18\xf0\x01 \x01(\x0b\x32*.zed.messages.AcceptTermsOfServiceResponseH\x00\x12\x33\n\rget_llm_token\x18\xeb\x01 \x01(\x0b\x32\x19.zed.messages.GetLlmTokenH\x00\x12\x44\n\x16get_llm_token_response\x18\xec\x01 \x01(\x0b\x32!.zed.messages.GetLlmTokenResponseH\x00\x42\t\n\x07payloadB\x10\n\x0e_responding_toB\x15\n\x13_original_sender_idB\t\n\x07_ack_idJ\x04\x08W\x10YJ\x06\x08\x9e\x01\x10\xa2\x01J\x06\x08\xa4\x01\x10\xa5\x01J\x06\x08\xa6\x01\x10\xaa\x01J\x06\x08\xb1\x01\x10\xba\x01J\x06\x08\xbc\x01\x10\xbd\x01J\x06\x08\xc1\x01\x10\xc4\x01J\x06\x08\xc5\x01\x10\xc6\x01J\x06\x08\xc8\x01\x10\xcb\x01J\x06\x08\xcd\x01\x10\xcf\x01J\x06\x08\xdd\x01\x10\xde\x01J\x06\x08\xe0\x01\x10\xe6\x01J\x06\x08\xf6\x01\x10\xf7\x01J\x06\x08\xf7\x01\x10\xff\x01J\x06\x08\xff\x01\x10\x81\x02\".\n\x05Hello\x12%\n\x07peer_id\x18\x01 \x01(\x0b\x32\x14.zed.messages.PeerId\"\x06\n\x04Ping\"\x05\n\x03\x41\x63k\"M\n\x05\x45rror\x12\x0f\n\x07message\x18\x01 \x01(\t\x12%\n\x04\x63ode\x18\x02 \x01(\x0e\x32\x17.zed.messages.ErrorCode\x12\x0c\n\x04tags\x18\x03 \x03(\t\"\x16\n\x14\x41\x63\x63\x65ptTermsOfService\"7\n\x1c\x41\x63\x63\x65ptTermsOfServiceResponse\x12\x17\n\x0f\x61\x63\x63\x65pted_tos_at\x18\x01 \x01(\x04\"\r\n\x0bGetLlmToken\"$\n\x13GetLlmTokenResponse\x12\r\n\x05token\x18\x01 \x01(\t*\xef\x02\n\tErrorCode\x12\x0c\n\x08Internal\x10\x00\x12\x11\n\rNoSuchChannel\x10\x01\x12\x10\n\x0c\x44isconnected\x10\x02\x12\r\n\tSignedOut\x10\x03\x12\x13\n\x0fUpgradeRequired\x10\x04\x12\r\n\tForbidden\x10\x05\x12\x0c\n\x08NeedsCla\x10\x07\x12\x13\n\x0fNotARootChannel\x10\x08\x12\x14\n\x10\x42\x61\x64PublicNesting\x10\t\x12\x13\n\x0f\x43ircularNesting\x10\n\x12\x13\n\x0fWrongMoveTarget\x10\x0b\x12\x10\n\x0cUnsharedItem\x10\x0c\x12\x11\n\rNoSuchProject\x10\r\x12$\n DevServerProjectPathDoesNotExist\x10\x10\x12\x19\n\x15RemoteUpgradeRequired\x10\x11\x12\x15\n\x11RateLimitExceeded\x10\x12\x12\x10\n\x0c\x43ommitFailed\x10\x13\"\x04\x08\x06\x10\x06\"\x04\x08\x0e\x10\x0f\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'zed_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_ERRORCODE']._serialized_start=1085
  _globals['_ERRORCODE']._serialized_end=1452
  _globals['_PEERID']._serialized_start=27
  _globals['_PEERID']._serialized_end=65
  _globals['_ENVELOPE']._serialized_start=68
  _globals['_ENVELOPE']._serialized_end=806
  _globals['_HELLO']._serialized_start=808
  _globals['_HELLO']._serialized_end=854
  _globals['_PING']._serialized_start=856
  _globals['_PING']._serialized_end=862
  _globals['_ACK']._serialized_start=864
  _globals['_ACK']._serialized_end=869
  _globals['_ERROR']._serialized_start=871
  _globals['_ERROR']._serialized_end=948
  _globals['_ACCEPTTERMSOFSERVICE']._serialized_start=950
  _globals['_ACCEPTTERMSOFSERVICE']._serialized_end=972
  _globals['_ACCEPTTERMSOFSERVICERESPONSE']._serialized_start=974
  _globals['_ACCEPTTERMSOFSERVICERESPONSE']._serialized_end=1029
  _globals['_GETLLMTOKEN']._serialized_start=1031
  _globals['_GETLLMTOKEN']._serialized_end=1044
  _globals['_GETLLMTOKENRESPONSE']._serialized_start=1046
  _globals['_GETLLMTOKENRESPONSE']._serialized_end=1082

# Start of the actual script
import os
import random
import base64
import json
import urllib.parse
import ssl
import time
import asyncio
import logging
import aiohttp
from aiohttp import web
import zstandard as zstd
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

import rsa

from google.protobuf.json_format import MessageToDict

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

BASE_URL = "https://zed.dev"
BASE_API_URL = "https://collab.zed.dev"
WS_URL = "wss://collab.zed.dev/rpc"
LLM_API_URL = "https://llm.zed.dev/completion"
PROXY_PORT = 9090
TOKEN_EXPIRY_WARNING_MINUTES = 50

highest_message_id = 0
llm_token = None
token_timestamp = None
server_peer_id = None
active_websocket = None
proxy_server_running = False

def generate_signin_url():
    port = random.randint(30000, 55000)
    (pubkey, privkey) = rsa.newkeys(2048, exponent=65537)
    der_public_key = rsa.PublicKey.save_pkcs1(pubkey, format='DER')
    b64_public_key = base64.urlsafe_b64encode(der_public_key).decode('utf-8')
    signin_url = f"{BASE_URL}/native_app_signin?native_app_port={port}&native_app_public_key={b64_public_key}"
    return signin_url, privkey

def decrypt_access_token(access_token_b64, private_key):
    encrypted_token = base64.urlsafe_b64decode(access_token_b64)
    try:
        decrypted = rsa.decrypt(encrypted_token, private_key)
        return decrypted.decode('utf-8')
    except Exception as e:
        try:
            decrypted = rsa.decrypt(encrypted_token, private_key, 'PKCS1_v1_5')
            return decrypted.decode('utf-8')
        except Exception as inner_e:
            raise Exception(f"Decryption failed (OAEP -> PKCS#1): {e}, {inner_e}")

def do_auth_flow():
    signin_url, private_key = generate_signin_url()
    print("\n!Sign in with GitHub (wait a few seconds after signing in for the redirect):\n", signin_url)
    print("\nPaste the full callback URL where the browser redirected you here:")
    callback_url = input().strip()

    parsed_url = urllib.parse.urlparse(callback_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    user_id = query_params.get('user_id', [''])[0]
    access_token_b64 = query_params.get('access_token', [''])[0]

    if not user_id or not access_token_b64:
        raise Exception("Missing user_id or access_token in callback URL.")

    decrypted_token = decrypt_access_token(access_token_b64, private_key)
    login_data = {"user_id": user_id, "auth": decrypted_token}
    with open('login.json', 'w') as f:
        json.dump(login_data, f, indent=2)
    logger.info("Success! Authentication data saved to login.json")
    logger.info(f"User ID: {user_id}")

def decode_envelope(data):
    try:
        dctx = zstd.ZstdDecompressor()
        decompressed_data = b''
        with dctx.stream_reader(data) as reader:
            while True:
                chunk = reader.read(8192)
                if not chunk:
                    break
                decompressed_data += chunk
        envelope = Envelope()
        envelope.ParseFromString(decompressed_data)
        return MessageToDict(envelope, preserving_proto_field_name=True)
    except Exception as e:
        hex_preview = ' '.join(f'{byte:02x}' for byte in data[:20]) + ('...' if len(data) > 20 else '')
        logger.error(f"Unable to decode message: {e}; data preview: {hex_preview}")
        return {"error": f"Unable to decode message: {e}"}

def compress_protobuf(data):
    return zstd.ZstdCompressor(level=-7).compress(data)

def create_message(message_type):
    global highest_message_id
    highest_message_id += 1
    message_id = highest_message_id
    envelope = Envelope(id=highest_message_id)

    getattr(envelope, message_type).SetInParent()
    return compress_protobuf(envelope.SerializeToString()), message_id

async def ping_periodically(websocket):
    while True:
        try:
            await websocket.ping()
            await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Error sending ping: {e}")
            break

async def handle_messages(websocket):
    global server_peer_id, llm_token, token_timestamp, active_websocket
    active_websocket = websocket
    try:
        async for message in websocket:
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message
            decoded = decode_envelope(message_bytes)
            if "hello" in decoded:
                server_peer_id = decoded.get('hello', {}).get('peer_id')
            elif "accept_terms_of_service_response" in decoded:
                await request_llm_token(websocket)
            elif ("get_llm_token_response" in decoded and 
                  'token' in decoded.get('get_llm_token_response', {})):
                llm_token = decoded['get_llm_token_response']['token']
                token_timestamp = time.time()
                logger.info(f"LLM token received at {time.ctime(token_timestamp)}")
                if not proxy_server_running:
                    asyncio.create_task(start_proxy_server())
                asyncio.create_task(monitor_token_expiration())
                logger.info("Closing WebSocket connection until token refresh is needed")
                await websocket.close()
                active_websocket = None
                return
    except ConnectionClosed:
        logger.info("Connection closed")
        active_websocket = None

async def request_llm_token(websocket):
    message, _ = create_message('get_llm_token')
    logger.info("Requesting the LLM token")
    await websocket.send(message)

async def request_accept_terms_of_service(websocket):
    message, _ = create_message('accept_terms_of_service')
    logger.info("Sending consent for the Zed Terms of Service")
    await websocket.send(message)

def format_content(content):
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return content

async def handle_message_request(request):
    global llm_token
    if not llm_token:
        return web.json_response({"error": "LLM token not available"}, status=500)
    try:
        body = await request.json()
        # Zed's Anthropic API weirdly doesn't want flat strings for messages
        if "messages" in body:
            for msg in body["messages"]:
                if "content" in msg:
                    msg["content"] = format_content(msg["content"])
        # But wants flat strings for system messages
        if "system" in body:
            if isinstance(body["system"], list):
                body["system"] = "\n".join([item["text"] for item in body["system"]])
            
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {llm_token}"}
        payload = {
            "provider": "anthropic",
            "model": body.get("model", "claude-3-5-sonnet"),
            "provider_request": body
        }
        if body.get("stream", False):
            return await handle_streaming_request(request, headers, payload)
        else:
            return await handle_non_streaming_request(headers, payload)
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return web.json_response({"error": str(e)}, status=500)

async def handle_non_streaming_request(headers, payload):
    async with aiohttp.ClientSession() as session:
        async with session.post(LLM_API_URL, headers=headers, json=payload) as r:
            if r.status != 200:
                text = await r.text()
                logger.error(f"LLM API error: {text}")
                return web.json_response({"error": text}, status=r.status)
            full_content, message_data = "", {}
            async for line in r.content:
                if not line:
                    continue
                try:
                    event = json.loads(line.decode('utf-8').strip())
                    et = event.get('type')
                    if et == "message_start":
                        message_data = event.get('message', {})
                    elif et == "content_block_delta" and event.get('delta', {}).get('type') == "text_delta":
                        full_content += event['delta'].get('text', '')
                    elif et == "message_delta" and 'usage' in event:
                        message_data['usage'] = event.get('usage')
                    elif et == "message_stop":
                        break
                except Exception as e:
                    logger.error(f"Error processing line: {e}")
            message_data['content'] = [{"type": "text", "text": full_content}]
            return web.json_response(message_data)

async def handle_streaming_request(request, headers, payload):
    response = web.StreamResponse()
    response.headers['Content-Type'] = 'text/event-stream'
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    await response.prepare(request)
    async with aiohttp.ClientSession() as session:
        async with session.post(LLM_API_URL, headers=headers, json=payload, timeout=60) as api_response:
            if api_response.status != 200:
                error_text = await api_response.text()
                logger.error(f"LLM API (stream) error: {error_text}")
                await response.write(f"data: {json.dumps({'error': error_text})}\n\n".encode())
                await response.write(b"data: [DONE]\n\n")
                return response
            async for line in api_response.content:
                if line:
                    await response.write(f"data: {line.decode('utf-8')}\n\n".encode())
            await response.write(b"data: [DONE]\n\n")
    return response

async def start_proxy_server():
    global proxy_server_running
    if proxy_server_running:
        logger.info("Proxy server already running, skipping startup")
        return
        
    proxy_server_running = True
    app = web.Application()
    
    app.router.add_post('/v1/messages', handle_message_request)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', PROXY_PORT)
    await site.start()
    logger.info(f"Proxy server started at http://localhost:{PROXY_PORT}")
    while True:
        await asyncio.sleep(3600)

def is_token_expiring():
    if not token_timestamp:
        return False
    return (time.time() - token_timestamp) / 60 >= TOKEN_EXPIRY_WARNING_MINUTES

async def monitor_token_expiration():
    while True:
        await asyncio.sleep(60)
        if is_token_expiring():
            elapsed = int((time.time() - token_timestamp) / 60)
            logger.warning(f"LLM token is approaching expiration (received {elapsed} minutes ago)")
            if active_websocket is None:
                logger.info("Reconnecting WebSocket for token refresh")
                asyncio.create_task(reconnect_for_token_refresh())
                return

async def reconnect_for_token_refresh():
    try:
        with open("login.json") as f:
            login_data = json.load(f)
        headers = {
            "authorization": login_data["user_id"] + " " + login_data["auth"],
            "x-zed-protocol-version": "68",
            "x-zed-app-version": "0.178.0",
            "x-zed-release-channel": "stable"
        }
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async for websocket in connect(WS_URL, additional_headers=headers, ssl=ssl_context):
            try:
                ping_task = asyncio.create_task(ping_periodically(websocket))
                await asyncio.sleep(2)
                await request_accept_terms_of_service(websocket)
                await handle_messages(websocket)
                break
            except ConnectionClosed:
                continue
            except Exception as e:
                logger.error(f"Error during token refresh: {e}")
                await asyncio.sleep(1)
                continue
            finally:
                ping_task.cancel()
                try:
                    await ping_task
                except asyncio.CancelledError:
                    pass
    except Exception as e:
        logger.error(f"Failed to reconnect for token refresh: {e}")

async def async_main():
    with open("login.json") as f:
        login_data = json.load(f)
    headers = {
        "authorization": login_data["user_id"] + " " + login_data["auth"],
        "x-zed-protocol-version": "68",
        "x-zed-app-version": "0.178.0",
        "x-zed-release-channel": "stable"
    }
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    logger.info("Connecting to the WebSocket server")
    async for websocket in connect(WS_URL, additional_headers=headers, ssl=ssl_context):
        try:
            ping_task = asyncio.create_task(ping_periodically(websocket))
            token_request_task = asyncio.create_task(delayed_token_request(websocket, delay=2))
            await handle_messages(websocket)
            break
        except ConnectionClosed:
            continue
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            await asyncio.sleep(1)
            continue
        finally:
            ping_task.cancel()
            try:
                await ping_task
            except asyncio.CancelledError:
                pass
            token_request_task.cancel()
            try:
                await token_request_task
            except asyncio.CancelledError:
                pass

    while True:
        await asyncio.sleep(3600)

async def delayed_token_request(websocket, delay=2):
    await asyncio.sleep(delay)
    await request_accept_terms_of_service(websocket)

def main():
    need_auth = False
    if not os.path.exists("login.json"):
        need_auth = True
    else:
        try:
            with open("login.json") as f:
                data = json.load(f)
                if not data.get("user_id") or not data.get("auth"):
                    need_auth = True
        except:
            need_auth = True

    if need_auth:
        do_auth_flow()
    else:
        logger.info("login.json seems to be present, skipping authentication flow")
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()