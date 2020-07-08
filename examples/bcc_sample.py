#!/usr/bin/env python3
#
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
#

import ctypes
import socket
import struct
from bcc import BPF

class NetEventData(ctypes.Structure):
	_fields_ = [
		('saddr', ctypes.c_uint),
		('daddr', ctypes.c_uint),
		('dport', ctypes.c_ushort),
		('sport', ctypes.c_ushort),
		('ipver', ctypes.c_ushort),
		('proto', ctypes.c_ushort),
		('dns_flag', ctypes.c_ushort),
		('saddr6', ctypes.c_uint * 4),
		('daddr6', ctypes.c_uint * 4),
		('dns', ctypes.c_char * 40),
		('name_len', ctypes.c_uint),
	]

class MmapArgs(ctypes.Structure):
	_fields_ = [
		('flags', ctypes.c_ulonglong),
		('prot', ctypes.c_ulonglong),
	]

class SensorUnion(ctypes.Union):
	_fields_ = [
		('mmap_args', MmapArgs),
		('fname', ctypes.c_char * 255),
		('net', NetEventData),
	]

class SensorEventMessage(ctypes.Structure):
	_fields_ = [
		('event_time', ctypes.c_ulonglong),
		('tid', ctypes.c_uint),
		('pid', ctypes.c_uint),
		('ev_type', ctypes.c_ubyte),
		('state', ctypes.c_ubyte),
		('uid', ctypes.c_uint),
		('ppid', ctypes.c_uint),
		('inode', ctypes.c_ulonglong),
		('device', ctypes.c_uint),
		('mnt_ns', ctypes.c_uint),
		('union', SensorUnion),
		('retval', ctypes.c_int),
		('start_time', ctypes.c_ulonglong),
	]

class Probe(object):
	def __init__(self, pp, pp_cb_name, is_kretprobe=False):
		self.pp = pp
		self.pp_cb_name = pp_cb_name
		self.is_kretprobe = is_kretprobe

class EventType(object):
	PROCESS_ARG = 0
	PROCESS_EXEC = 1
	PROCESS_EXIT = 2
	PROCESS_CLONE = 3
	FILE_READ = 4
	FILE_WRITE = 5
	FILE_CREATE = 6
	FILE_MMAP = 8
	FILE_TEST = 9
	CONNECT_PRE = 10
	CONNECT_ACCEPT = 11
	DNS_RESPONSE = 12
	WEB_PROXY = 13
	FILE_DELETE = 14

	event_type_map = {
		PROCESS_ARG : 'PROCESS_ARG',
		PROCESS_EXEC : 'PROCESS_EXEC',
		PROCESS_CLONE : 'PROCESS_CLONE',
		FILE_READ : 'FILE_READ',
		FILE_WRITE : 'FILE_WRITE',
		FILE_CREATE : 'FILE_CREATE',
		FILE_MMAP : 'FILE_MMAP',
		CONNECT_PRE : 'NET_CONNECT',
		CONNECT_ACCEPT : 'NET_ACCEPT',
		DNS_RESPONSE : 'DNS_RESPONSE',
		WEB_PROXY : 'WEB_PROXY',
		FILE_DELETE : 'FILE_DELETE',
	}

	PP_NO_EXTRA_DATA = 0
	PP_ENTRY_POINT = 1
	PP_PATH_COMPONENT = 2
	PP_FINALIZE = 3

	msg_state = {
		PP_NO_EXTRA_DATA : 'PP_NO_EXTRA_DATA',
		PP_ENTRY_POINT : 'PP_ENTRY_POINT',
		PP_PATH_COMPONENT : 'PP_PATH_COMPONENT',
		PP_FINALIZE : 'PP_FINALIZE',
	}

EVENT_TYPE = EventType()

class FileEvent(object):
	filepath = ""
	def __init__(self, event_msg):
		self.ev_type = event_msg.ev_type
		self.event_time = event_msg.event_time
		self.tid = event_msg.tid
		self.pid = event_msg.pid
		self.ppid = event_msg.ppid
		self.uid = event_msg.uid
		self.inode = event_msg.inode
		self.device = event_msg.device
		self.mnt_ns = event_msg.mnt_ns
		if event_msg.ev_type in EVENT_TYPE.event_type_map:
			self.event_type_str = EVENT_TYPE.event_type_map[event_msg.ev_type]
		else:
			self.event_type_str = "UNKNOWN"

	def update(self, event_msg):
		if event_msg.state == EVENT_TYPE.PP_PATH_COMPONENT:
			self.filepath = '/%s%s' % (event_msg.union.fname.decode(), self.filepath)
		elif (event_msg.state == EVENT_TYPE.PP_FINALIZE):
			return self.logstr()

	# Perhaps add mmap args
	# uid may not always be set
	def logstr(self):
		file_event_str = '%lu %s pid:%d ppid:%d uid:%d mnt_ns:%d %lu[%#08x]%s' % (
			self.event_time,
			self.event_type_str,
			self.pid,
			self.ppid,
			self.uid,
			self.mnt_ns,
			self.inode,
			self.device,
			self.filepath,
		)
		return file_event_str

class CloneEvent(object):
	filepath = ""
	def __init__(self, event_msg):
		self.event_time = event_msg.event_time
		self.tid = event_msg.tid
		self.pid = event_msg.pid
		self.uid = event_msg.uid
		self.start_time = event_msg.start_time
		self.ppid = event_msg.ppid
		self.inode = event_msg.inode
		self.device = event_msg.device
		self.mnt_ns = event_msg.mnt_ns
		self.comm = event_msg.union.fname.decode()

	def logstr(self):
		pathstr = self.filepath
		if not pathstr:
			pathstr = self.comm
		event_str = '%lu FORK pid:%d ppid:%d uid:%d start_time:%lu mnt_ns:%s %lu[%#08x]%s' % (
			self.event_time,
			self.pid,
			self.ppid,
			self.uid,
			self.start_time,
			self.mnt_ns,
			self.inode,
			self.device,
			pathstr,
		)
		return event_str

#
# Eventually handle script filepath and exe filepath loads
#
class ExecEvent(object):
	retval = -1
	finalize_filepath = False
	set_entrypoint_data = False
	script_path = ""
	filepath = ""

	def __init__(self, event_msg):
		self.event_time = event_msg.event_time
		self.tid = event_msg.tid
		self.pid = event_msg.pid
		self.arg_str = event_msg.union.fname.decode()
		self.start_time = 0
		self.ppid = 0
		self.uid = 0
		self.inode = 0
		self.device = 0
		self.mnt_ns = 0

	def update(self, event_msg):
#		print(EVENT_TYPE.event_type_map[event_msg.ev_type], EVENT_TYPE.msg_state[event_msg.state])
		if event_msg.ev_type == EVENT_TYPE.PROCESS_ARG:
			if event_msg.state == EVENT_TYPE.PP_FINALIZE:
				self.retval = event_msg.retval
				return self.logstr()
			else:
				self.arg_str += ' ' + event_msg.union.fname.decode()

		if event_msg.ev_type == EVENT_TYPE.PROCESS_EXEC:
			if event_msg.state == EVENT_TYPE.PP_ENTRY_POINT:
				self.start_time = event_msg.start_time
				self.ppid = event_msg.ppid
				self.uid = event_msg.uid
				self.inode = event_msg.inode
				self.device = event_msg.device
				self.mnt_ns = event_msg.mnt_ns
			elif event_msg.state == EVENT_TYPE.PP_PATH_COMPONENT:
				self.filepath = '/%s%s' % (event_msg.union.fname.decode(), self.filepath)
			elif (event_msg.state == EVENT_TYPE.PP_FINALIZE):
				self.finalize_filepath = True

	def logstr(self):
		args = self.arg_str

		exec_event_str = '%lu EXEC pid:%d ppid:%d uid:%d start_time:%lu mnt_ns:%s %lu[%#08x]%s ret:%d \'%s\'' % (
			self.event_time,
			self.pid,
			self.ppid,
			self.uid,
			self.start_time,
			self.mnt_ns,
			self.inode,
			self.device,
			self.filepath,
			self.retval,
			self.arg_str,
		)
		return exec_event_str


class NetEvent(object):
	def __init__(self, event_msg):
		self.event_time = event_msg.event_time
		self.tid = event_msg.tid
		self.pid = event_msg.pid

		self.ppid = event_msg.ppid
		self.start_time = event_msg.start_time
		self.mnt_ns = event_msg.mnt_ns
		# Not in 4.4 suse kernels
		self.uid = event_msg.uid

		self.ev_type_str = EVENT_TYPE.event_type_map[event_msg.ev_type]

		self.flow = None
		self.family = None
		self.pack_saddr = None
		self.pack_daddr = None
		self.proto = "TCP"
		if event_msg.union.net.proto == 17:
			self.proto = "UDP"

		# Should not have to run htons here oh well
		self.sport = int(event_msg.union.net.sport)
		self.dport = int(event_msg.union.net.dport)

		if event_msg.ev_type == EVENT_TYPE.CONNECT_ACCEPT:
			if event_msg.union.net.proto == 17:
				self.sport = socket.htons(int(event_msg.union.net.sport))
				self.dport = socket.htons(int(event_msg.union.net.dport))
			self.flow = "rx"
		elif event_msg.ev_type == EVENT_TYPE.CONNECT_PRE:
			self.flow = "tx"
			self.dport = socket.htons(int(event_msg.union.net.dport))

		# AF_INET
		if event_msg.union.net.ipver == socket.AF_INET:
			self.family = socket.AF_INET
			self.pack_saddr = struct.pack("I", event_msg.union.net.saddr)
			self.pack_daddr = struct.pack("I", event_msg.union.net.daddr)
		# AF_INET6
		elif event_msg.union.net.ipver == socket.AF_INET6:
			self.family = socket.AF_INET6
			self.pack_saddr = struct.pack("IIII",
				event_msg.union.net.saddr6[0],
				event_msg.union.net.saddr6[1],
				event_msg.union.net.saddr6[2],
				event_msg.union.net.saddr6[3],
			)
			self.pack_daddr = struct.pack("IIII",
				event_msg.union.net.daddr6[0],
				event_msg.union.net.daddr6[1],
				event_msg.union.net.daddr6[2],
				event_msg.union.net.daddr6[3],
			)


	def logstr(self):
		net_event_str = '%lu %s %s  pid:%d %s:%d -> %s:%d' % (
			self.event_time,
			self.ev_type_str,
			self.proto,
			self.pid,
			socket.inet_ntop(self.family, self.pack_saddr),
			self.sport,
			socket.inet_ntop(self.family, self.pack_daddr),
			self.dport,
		)
		return net_event_str

class DNSEvent(object):
	def __init__(self, event_msg):
		self.event_time = event_msg.event_time
		self.tid = event_msg.tid
		self.pid = event_msg.pid

clone_event_table = {}
exec_event_table = {}
file_event_table = {}
dns_event_table = {}


def handle_exit_event(event_msg):
	exit_str = '%lu EXIT pid:%d start_time:%lu' % (
		event_msg.event_time, event_msg.pid, event_msg.start_time,
	)
	return exit_str

def handle_clone_event(event_msg):
	key = (event_msg.event_time, event_msg.pid)
	if (event_msg.state == EVENT_TYPE.PP_NO_EXTRA_DATA):
		fork_str = '%lu FORK pid:%d ppid:%d uid:%d start_time:%lu %s' % (
			event_msg.event_time,
			event_msg.pid,
			event_msg.ppid,
			event_msg.uid,
			event_msg.start_time,
			event_msg.union.fname.decode(),
		)
		if key in clone_event_table:
			del clone_event_table[key]
		return fork_str
	if event_msg.state == EVENT_TYPE.PP_ENTRY_POINT:
		if key in clone_event_table:
			print("Key shouldn't exist")
			del clone_event_table[key]
		clone_event_table[key] = CloneEvent(event_msg)
		return None

	if not key in clone_event_table:
		print("Missing clone event entry")
		return None

	if event_msg.state == EVENT_TYPE.PP_PATH_COMPONENT:
		clone_event_table[key].filepath = '/%s%s' % (
			event_msg.union.fname.decode(),
			clone_event_table[key].filepath)
		return None

	if event_msg.state == EVENT_TYPE.PP_FINALIZE:
		clone_event = clone_event_table[key]
		del clone_event_table[key]
		return clone_event.logstr()

def handle_exec_event(event_msg):
	key = event_msg.tid
	if key in exec_event_table:
		ret = exec_event_table[key].update(event_msg)
		if ret:
			del exec_event_table[key]
			return ret
	else:
		exec_event_table[key] = ExecEvent(event_msg)

def handle_file_event(event_msg):
	key = (event_msg.tid, event_msg.event_time)
	if key in file_event_table:
		if file_event_table[key].ev_type != event_msg.ev_type:
			print("Miss-match of file event types")
			return None

		ret = file_event_table[key].update(event_msg)
		if ret:
			del file_event_table[key]
			return ret
	else:
		if event_msg.state > EVENT_TYPE.PP_ENTRY_POINT:
			print("Missing event data")
		file_event_table[key] = FileEvent(event_msg)

def handle_dns_event(event_msg):
	pass
def handle_network_event(event_msg):
	ret = NetEvent(event_msg)
	return ret.logstr()

def perf_event_cb(cpu, data, size):
	event_msg = ctypes.cast(data, ctypes.POINTER(SensorEventMessage)).contents
	if event_msg.ev_type == EVENT_TYPE.PROCESS_CLONE:
		ret = handle_clone_event(event_msg)
		if ret:
			print(ret)
	elif event_msg.ev_type == EVENT_TYPE.PROCESS_EXIT:
		handle_exit_event(event_msg)
	elif (event_msg.ev_type == EVENT_TYPE.PROCESS_EXEC or 
		event_msg.ev_type == EVENT_TYPE.PROCESS_ARG):
		ret = handle_exec_event(event_msg)
		if ret:
			print(ret)
	elif (event_msg.ev_type == EVENT_TYPE.CONNECT_PRE or
		  event_msg.ev_type == EVENT_TYPE.CONNECT_ACCEPT):
		ret = handle_network_event(event_msg)
		if ret:
			print(ret)
	elif (event_msg.ev_type == EVENT_TYPE.DNS_RESPONSE or
		  event_msg.ev_type == EVENT_TYPE.WEB_PROXY):
		handle_dns_event(event_msg)
	elif (event_msg.ev_type == EVENT_TYPE.FILE_WRITE or 
		  event_msg.ev_type == EVENT_TYPE.FILE_MMAP or
		  event_msg.ev_type == EVENT_TYPE.FILE_CREATE or
		  event_msg.ev_type == EVENT_TYPE.FILE_DELETE):
		ret = handle_file_event(event_msg)
		if ret:
			print(ret)


def load_script(bcc_kernel_script):
	with open(bcc_kernel_script, 'r') as fh:
		bpf_text = fh.read()
	return BPF(text=bpf_text)

def load_perf_callback(bcc):
	bcc['events'].open_perf_buffer(perf_event_cb, page_cnt=128)

def attach_probes(bcc):
	probes = [
		# PID Clone Events
		Probe(
			pp='wake_up_new_task',
			pp_cb_name='on_wake_up_new_task',
		),

		# cache eviction relate probe
		Probe(
			pp='security_file_free',
			pp_cb_name='on_security_file_free',
		),

		# Process Exit Events
		Probe(
			pp='security_task_free',
			pp_cb_name='on_security_task_free',
		),

		# File Events
		Probe(
			pp='__vfs_write',
			pp_cb_name='trace_write_entry',
		),
		Probe(
			pp='security_mmap_file',
			pp_cb_name='on_security_mmap_file',
		),
		Probe(
			pp='security_file_open',
			pp_cb_name='on_security_file_open',
		),

		# execve and execveat syscalls
		Probe(
			pp=bcc.get_syscall_fnname("execve"),
			pp_cb_name='syscall__on_sys_execve',
		),
		Probe(
			pp=bcc.get_syscall_fnname("execveat"),
			pp_cb_name='syscall__on_sys_execveat',
		),
		Probe(
			pp=bcc.get_syscall_fnname("execve"),
			pp_cb_name='after_sys_execve',
			is_kretprobe=True,
		),
		Probe(
			pp=bcc.get_syscall_fnname("execveat"),
			pp_cb_name='after_sys_execve',
			is_kretprobe=True,
		),

		# DNS TCP Network Events
		Probe(
			pp='tcp_sendmsg',
			pp_cb_name='trace_udp_sendmsg',
		),

		#DNS UDP recvmsg Events
		Probe(
			pp='udp_recvmsg',
			pp_cb_name='trace_udp_recvmsg',
		),
		Probe(
			pp='udpv6_recvmsg',
			pp_cb_name='trace_udp_recvmsg',
		),
		Probe(
			pp='udp_recvmsg',
			pp_cb_name='trace_udp_recvmsg_return',
			is_kretprobe=True,
		),
		Probe(
			pp='udpv6_recvmsg',
			pp_cb_name='trace_udp_recvmsg_return',
			is_kretprobe=True,
		),

		# UDP Tx Events
		Probe(
			pp='udp_sendmsg',
			pp_cb_name='trace_udp_sendmsg',
		),
		Probe(
			pp='udpv6_sendmsg',
			pp_cb_name='trace_udp_sendmsg',
		),
		Probe(
			pp='udp_sendmsg',
			pp_cb_name='trace_udp_sendmsg_return',
			is_kretprobe=True,
		),
		Probe(
			pp='udpv6_sendmsg',
			pp_cb_name='trace_udp_sendmsg_return',
			is_kretprobe=True,
		),

		# UDP Rx Events
		Probe(
			pp='__skb_recv_udp',
			pp_cb_name='trace_skb_recv_udp',
			is_kretprobe=True,
		),

		# TCP Connect Events
		Probe(
			pp='tcp_v4_connect',
			pp_cb_name='trace_connect_v4_entry',
		),
		Probe(
			pp='tcp_v6_connect',
			pp_cb_name='trace_connect_v6_entry',
		),
		Probe(
			pp='tcp_v4_connect',
			pp_cb_name='trace_connect_v4_return',
			is_kretprobe=True,
		),
		Probe(
			pp='tcp_v6_connect',
			pp_cb_name='trace_connect_v6_return',
			is_kretprobe=True,
		),

		# TCP Accept Events
		Probe(
			pp='inet_csk_accept',
			pp_cb_name='trace_accept_return',
			is_kretprobe=True,
		),
	]

	for probe in probes:
		if (probe.is_kretprobe):
			bcc.attach_kretprobe(event=probe.pp, fn_name=probe.pp_cb_name)
		else:
			bcc.attach_kprobe(event=probe.pp, fn_name=probe.pp_cb_name)

if __name__ == '__main__':
	def main():
		import sys

		bpf_source = 'bcc_sensor.c'
		if len(sys.argv) > 1:
			bpf_source = sys.argv[1]

		bcc = load_script(bcc_kernel_script=bpf_source)
		attach_probes(bcc)
		load_perf_callback(bcc)
		while True:
			bcc.perf_buffer_poll()

	main()
