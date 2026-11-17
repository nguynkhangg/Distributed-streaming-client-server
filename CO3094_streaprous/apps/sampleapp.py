#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the "MIT License Agreement". Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#


"""
app.sampleapp
~~~~~~~~~~~~~~~~~

"""

import sys
import os
import importlib.util
import json

from   daemon import StreapRous
from .chat import ChatService

app = StreapRous()
chat_service = ChatService()


def _chat_json(data):
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def _chat_body(body):
    try:
        data = json.loads(body or "{}")
    except json.JSONDecodeError:
        raise ValueError("request body must be valid JSON")
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    return data


def _chat_result(action):
    try:
        return _chat_json(action())
    except (KeyError, ValueError) as error:
        return _chat_json({"error": str(error)})

@app.route('/login', methods=['POST'])
def login(headers="guest", body="anonymous"):
    """
    Handle user login via POST request.

    This route simulates a login process and prints the provided headers and body
    to the console.

    :param headers (str): The request headers or user identifier.
    :param body (str): The request body or login payload.
    """
    print("[SampleApp] Logging in {} to {}".format(headers, body))
    data = {"message": "Welcome to the RESTful TCP WebApp"}

    # Convert to JSON string
    json_str = json.dumps(data)
    return (json_str.encode("utf-8"))

@app.route("/echo", methods=["POST"])
def echo(headers="guest", body="anonymous"):
    print("[SampleApp] received body {}".format(body))

    try:
        message = json.loads(body)
        data = {"received": message }
        # Convert to JSON string
        json_str = json.dumps(data)
        return (json_str.encode("utf-8"))
    except json.JSONDecodeError:
        data = {"error": "Invalid JSON"}
        # Convert to JSON string
        json_str = json.dumps(data)
        return (json_str.encode("utf-8"))


@app.route('/api/peers', methods=['GET'])
def list_peers(headers, body):
    return _chat_result(lambda: {"peers": chat_service.list_peers()})


@app.route('/api/peers/register', methods=['POST'])
def register_peer(headers, body):
    def register():
        data = _chat_body(body)
        peer = chat_service.register_peer(
            data.get("peerId"),
            data.get("username"),
            data.get("ip"),
            data.get("port"),
        )
        return {"peer": peer, "peers": chat_service.list_peers()}
    return _chat_result(register)


@app.route('/api/peers/unregister', methods=['POST'])
def unregister_peer(headers, body):
    def unregister():
        data = _chat_body(body)
        return chat_service.unregister_peer(data.get("peerId"))
    return _chat_result(unregister)


@app.route('/api/channels', methods=['GET'])
def list_channels(headers, body):
    def list_joined_channels():
        peer_id = headers.get("x-peer-id", "")
        return {"channels": chat_service.list_channels(peer_id)}
    return _chat_result(list_joined_channels)


@app.route('/api/channels/create', methods=['POST'])
def create_channel(headers, body):
    def create():
        data = _chat_body(body)
        channel = chat_service.create_channel(data.get("peerId"), data.get("name"))
        return {"channel": channel}
    return _chat_result(create)


@app.route('/api/channels/join', methods=['POST'])
def join_channel(headers, body):
    def join():
        data = _chat_body(body)
        channel = chat_service.join_channel(data.get("peerId"), data.get("channelId"))
        return {"channel": channel}
    return _chat_result(join)


@app.route('/api/messages', methods=['GET'])
def list_messages(headers, body):
    def list_channel_messages():
        peer_id = headers.get("x-peer-id", "")
        channel_id = headers.get("x-channel-id", "")
        return {"messages": chat_service.list_messages(peer_id, channel_id)}
    return _chat_result(list_channel_messages)


@app.route('/api/messages', methods=['POST'])
def send_message(headers, body):
    def send():
        data = _chat_body(body)
        message = chat_service.send_message(
            data.get("peerId"),
            data.get("channelId"),
            data.get("text"),
        )
        return message
    return _chat_result(send)


@app.route('/api/messages/direct', methods=['POST'])
def send_private_message(headers, body):
    def send():
        data = _chat_body(body)
        return chat_service.send_private_message(
            data.get("peerId"),
            data.get("to"),
            data.get("text"),
        )
    return _chat_result(send)


@app.route('/api/messages/poll', methods=['POST'])
def poll_messages(headers, body):
    def poll():
        data = _chat_body(body)
        return {"events": chat_service.poll_events(data.get("peerId"))}
    return _chat_result(poll)


@app.route('/hello', methods=['PUT'])
async def hello(headers, body):
    """
    Handle greeting via PUT request.

    This route prints a greeting message to the console using the provided headers
    and body.

    :param headers (str): The request headers or user identifier.
    :param body (str): The request body or message payload.
    """
    print("[SampleApp] ['PUT'] **ASYNC** Hello in {} to {}".format(headers, body))
    data =  {"id": 1, "name": "Alice", "email": "alice@example.com"}

    # Convert to JSON string
    json_str = json.dumps(data)
    return (json_str.encode("utf-8"))

def create_sampleapp(ip, port):
    # Prepare and launch the RESTful application
    app.prepare_address(ip, port)
    app.run()

