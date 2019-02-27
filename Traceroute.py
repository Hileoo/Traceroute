#!/usr/bin/python
# -*- coding: UTF-8 -*-

from socket import *
import socket
import os
import sys
import struct
import time

ICMP_ECHO_REQUEST = 8  # ICMP type code for echo request messages
ICMP_ECHO_REPLY = 0  # ICMP type code for echo reply messages
PACKET_SENT = 0
PACKET_RECEIVED = 0

DESTINATION_REACHED = "REACHED"
SOCKET_TIMEOUT_CODE = "TIMEOUT"


def checksum(source_string):
    check_sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = (source_string[count+1]) * 256 + (source_string[count])
        check_sum = check_sum + this_val
        check_sum = check_sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        check_sum = check_sum + (source_string[len(source_string) - 1])
        check_sum = check_sum & 0xffffffff

    check_sum = (check_sum >> 16) + (check_sum & 0xffff)
    check_sum = check_sum + (check_sum >> 16)
    answer = ~check_sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    # Take the right checksum and then add them to the header
    if sys.platform == 'darwin':
        # Convert 16-bits integers of hosts to network byte-order
        answer = socket.htons(answer) & 0xffff
    else:
        answer = socket.htons(answer)

    return answer


def receive_one_ping(icmp_socket, ID, timeout, destination_address):
    global PACKET_RECEIVED

    start_select = time.time()
    timeout_limit = start_select + timeout

    while (timeout_limit - time.time()) > 0:
        try:
            received_packet, (addr, x) = icmp_socket.recvfrom(1024)
        except socket.timeout:
            break
        received_time = time.time()

        header = received_packet[20:28]

        # Unpack the packet header for useful information, including the ID
        request_type, code, check_sum, packet_ID, sequence = struct.unpack("bbHHh", header)

        if request_type == 11 and code == 0:
            PACKET_RECEIVED = PACKET_RECEIVED + 1
            return (received_time - start_select, addr, None)
        elif request_type == 0 and code == 0:
            PACKET_RECEIVED = PACKET_RECEIVED + 1
            return (received_time - start_select, addr, DESTINATION_REACHED)

    return (None, None, SOCKET_TIMEOUT_CODE)


def send_one_ping(icmp_socket, destination_address, ID):
    global PACKET_SENT

    # Header: request_type (8), code(8), check_sum (16), packet_ID (16), sequence (16)
    test_checksum = 0

    # Build ICMP header
    icmp_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, test_checksum, ID, 1)

    # Build the time of sending
    record = struct.pack("d", time.time())

    # Checksum ICMP packet using given function
    test_checksum = checksum(icmp_header + record)

    # Insert checksum into packet
    icmp_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, test_checksum, ID, 1)

    # Insert time of sending into packet
    icmp_packet = icmp_header + record

    # Send packet using socket
    icmp_socket.sendto(icmp_packet, (destination_address, 1))

    # Increase the count amount of the packet had been sent
    PACKET_SENT = PACKET_SENT + 1


def do_one_ping(destination_address, timeout, ttl):
    icmp = socket.getprotobyname("icmp")

    # Create ICMP socket
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)

    # Set the TTL of a socket (and thus the packet leaving it)
    my_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)  # socket.setsockopt(level, optname, value)
    my_socket.settimeout(timeout)

    my_ID = os.getpid() & 0xFFFF

    # Call send_one_ping function
    send_one_ping(my_socket, destination_address, my_ID)

    # Call receive_one_ping function
    delay = receive_one_ping(my_socket, my_ID, timeout, destination_address)

    # Close ICMP socket
    my_socket.close()

    # Return total network delay
    return delay


def trace_route(host, timeout, max_hops):
    destination = socket.gethostbyname(host)
    print("Traceroute to {0} ({1}), {2} hops max".format(host, destination, max_hops))

    for ttl in range(1, max_hops + 1):
        print("{}:".format(ttl), end=' ')  # Avoid for creating a new line
        previous_address = None
        check = None  # Check whether the program reaches the destination

        # Repeated measurements for each node
        for i in range(3):
            delay, this_address, check = do_one_ping(destination, timeout, ttl)
            if not delay:
                print("*Timeout ", end='')
                previous_address = this_address
                continue

            if not previous_address == this_address:
                try:
                    host, _, _ = socket.gethostbyaddr(this_address)
                except:
                    host = this_address

                print("{} ({})  {:.3f} ms".format(host, this_address, delay*1000), end=' ')
            else:
                print(' {:.3f} ms'.format(delay*1000), end=' ')

            previous_address = this_address

        print("")  # Start a new line

        if check == DESTINATION_REACHED:
            print("")
            break

    # Calculate the packet lose rate
    print("Display result:")
    lose_rate = ((PACKET_SENT - PACKET_RECEIVED)/PACKET_SENT)
    print("The Packet Lose Rate is: {:.3f} %".format(lose_rate*100))


trace_route("www.lancaster.ac.uk", 1, 30)  # Parameters: ("host", "timeout", "max_hops")