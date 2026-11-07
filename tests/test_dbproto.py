"""Wire-protocol codecs. Frames are built by hand so the expectations are explicit."""

from __future__ import annotations

import socket
import struct

from relift.modules import dbproto
from relift.modules.base import TCPConn


def pair():
    """Two connected sockets: the module writes one, the test reads the other."""
    left, right = socket.socketpair()
    return TCPConn(sock=left, host="test", port=0), right


# -- primitives --------------------------------------------------------------
def test_int32_round_trip():
    assert dbproto.unpack_int32(dbproto.pack_int32(0)) == 0
    assert dbproto.unpack_int32(dbproto.pack_int32(-1)) == -1
    assert dbproto.unpack_int32(dbproto.pack_int32(2**31 - 1)) == 2**31 - 1


def test_pack_is_big_endian():
    assert dbproto.pack_int32(1) == b"\x00\x00\x00\x01"


def test_int16_round_trip():
    assert dbproto.unpack_int16(dbproto.pack_int16(5432)) == 5432


# -- PostgreSQL --------------------------------------------------------------
def test_startup_message_declares_its_own_length():
    payload = dbproto.pg_startup_payload("probe", "appdb")
    assert dbproto.unpack_int32(payload[:4]) == len(payload)
    assert payload[4:8] == b"\x00\x03\x00\x00"  # protocol 3.0


def test_startup_message_carries_user_and_database():
    payload = dbproto.pg_startup_payload("probe", "appdb")
    assert b"user\x00probe\x00" in payload
    assert b"database\x00appdb\x00" in payload
    assert payload.endswith(b"\x00")


def test_ssl_request_is_the_eight_byte_magic():
    request = dbproto.pg_ssl_request()
    assert len(request) == 8
    assert dbproto.unpack_int32(request[:4]) == 8
    assert dbproto.unpack_int32(request[4:8]) == 80877103


def test_send_message_writes_type_byte_before_length():
    """Regression: the length used to come first, which the server read as a
    zero message type and rejected with a very confusing FATAL."""
    conn, peer = pair()
    dbproto.pg_send_message(conn, b"Q", b"SELECT 1")
    frame = peer.recv(4096)
    assert frame[0:1] == b"Q"
    assert dbproto.unpack_int32(frame[1:5]) == len(frame) - 1
    assert frame[5:] == b"SELECT 1"
    conn.close()
    peer.close()


def test_read_message_parses_an_authentication_frame():
    conn, peer = pair()
    body = dbproto.pack_int32(10) + b"SCRAM-SHA-256\x00\x00"
    peer.sendall(b"R" + dbproto.pack_int32(len(body) + 4) + body)
    kind, payload = dbproto.pg_read_message(conn)
    assert kind == b"R"
    assert dbproto.unpack_int32(payload[:4]) == 10
    assert b"SCRAM-SHA-256" in payload
    conn.close()
    peer.close()


def test_read_message_rejects_an_implausible_length():
    conn, peer = pair()
    peer.sendall(b"R" + dbproto.pack_int32(1))
    try:
        dbproto.pg_read_message(conn)
    except OSError as exc:
        assert "implausible" in str(exc)
    else:  # pragma: no cover - the frame above is deliberately invalid
        raise AssertionError("a 1-byte frame should have been refused")
    conn.close()
    peer.close()


# -- MySQL -------------------------------------------------------------------
def test_mysql_packet_is_three_byte_length_plus_sequence():
    conn, peer = pair()
    peer.sendall(b"\x03\x00\x00" + b"\x02" + b"abc")
    sequence, payload = dbproto.mysql_read_packet(conn)
    assert sequence == 2
    assert payload == b"abc"
    conn.close()
    peer.close()


# -- Redis -------------------------------------------------------------------
def test_redis_ping_is_encoded_as_resp_array():
    conn, peer = pair()
    peer.sendall(b"+PONG\r\n")
    reply = dbproto.redis_command(conn, "PING")
    assert reply.kind == "status"
    assert reply.value == "PONG"
    assert peer.recv(4096) == b"*1\r\n$4\r\nPING\r\n"
    conn.close()
    peer.close()


def test_redis_error_reply_is_data_not_an_exception():
    conn, peer = pair()
    peer.sendall(b"-NOAUTH Authentication required.\r\n")
    reply = dbproto.redis_command(conn, "PING")
    assert reply.kind == "error"
    assert "NOAUTH" in reply.value
    assert reply.ok is False
    conn.close()
    peer.close()


def test_redis_bulk_reply():
    conn, peer = pair()
    peer.sendall(b"$5\r\nhello\r\n")
    reply = dbproto.redis_command(conn, "GET", "k")
    assert reply.kind == "bulk"
    assert reply.value == "hello"
    conn.close()
    peer.close()


def test_redisreply_ok_semantics():
    assert dbproto.RedisReply(kind="status", value="OK").ok is True
    assert dbproto.RedisReply(kind="status", value="PONG").ok is False
    assert dbproto.RedisReply(kind="error", value="OK").ok is False
    assert dbproto.RedisReply(kind="integer", value="1").ok is False


# -- BSON --------------------------------------------------------------------
def test_bson_round_trip_every_supported_type():
    document = {
        "string": "relift",
        "int": 42,
        "big": 2**40,
        "flag": True,
        "ratio": 1.5,
        "nested": {"inner": "value", "n": -3},
        "list": ["a", "b"],
        "raw": b"\x00\x01\xff",
        "nothing": None,
    }
    decoded, consumed = dbproto.bson_decode(dbproto.bson_encode(document))
    assert consumed == len(dbproto.bson_encode(document))
    for key, value in document.items():
        assert decoded[key] == value, key


def _element(marker, name, payload):
    return marker + name.encode("utf-8") + b"\x00" + payload


def test_bson_decode_a_hand_built_mongo_hello():
    elements = [
        _element(b"\x08", "isWritablePrimary", b"\x01"),
        _element(b"\x10", "maxWireVersion", struct.pack("<i", 21)),
        _element(b"\x10", "minWireVersion", struct.pack("<i", 0)),
        _element(b"\x01", "ok", struct.pack("<d", 1.0)),
        _element(b"\x12", "uptimeMillis", struct.pack("<q", 1234567890123)),
        _element(b"\x09", "localTime", struct.pack("<q", 1700000000000)),
        # BSON lengths are little-endian; pack_int32 is the big-endian helper
        # used by the PostgreSQL framing, so it must not be reused here.
        _element(b"\x02", "version", struct.pack("<i", 7) + b"7.0.14\x00"),
        _element(
            b"\x04", "hosts", dbproto.bson_encode({"0": "a:27017", "1": "b:27017"})
        ),
    ]
    body = b"".join(elements) + b"\x00"
    document = struct.pack("<i", len(body) + 4) + body

    decoded, consumed = dbproto.bson_decode(document)
    assert consumed == len(document)
    assert decoded["isWritablePrimary"] is True
    assert decoded["maxWireVersion"] == 21
    assert decoded["minWireVersion"] == 0
    assert decoded["ok"] == 1.0
    assert decoded["uptimeMillis"] == 1234567890123
    assert decoded["version"] == "7.0.14"
    assert decoded["hosts"] == ["a:27017", "b:27017"]


def test_bson_decode_tolerates_a_truncated_document():
    assert dbproto.bson_decode(b"") == ({}, 0)
    assert dbproto.bson_decode(b"\x05\x00") == ({}, 0)
