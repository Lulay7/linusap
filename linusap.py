from tokenize import String
from typing import Optional
from xmlrpc.client import Boolean

from volatility3.framework.configuration import requirements
from volatility3.framework import symbols, exceptions, renderers, interfaces
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.framework.interfaces import plugins

from abc import ABC, abstractmethod
import re

## Task structure
class TaskInfo():
	'''
	Structure that contains necessary information to classify a task
	'''
	def __init__(self, _task):
		self.pid = _task.pid
		self.ppid = _task.parent.pid
		self.name = utility.array_to_string(_task.comm)
		self.service = "NONE"
		self.parentService = "NONE"

		kn = _task.cgroups.dfl_cgrp.kn
		if kn:
			servicePtr = kn.name
			self.service = utility.pointer_to_string(servicePtr, 255)
			
			parentPtr = kn.parent
			if parentPtr:
				self.parentService = utility.pointer_to_string(parentPtr.name, 255)


	


## Strategy interface 
class LinuxASEP(ABC):
	'''
	Interface for ASEP detection strategy
	'''

	# Constructor
	def __init__(self, _taskInfo):
		self.taskInfo = _taskInfo
	
	# Return True if ASEP invoked the task
	@abstractmethod
	def detect(self) -> Boolean:
		pass

	# Return name of the ASEP
	@abstractmethod
	def getASEPName(self) -> String:
		pass


## Concrete strategies
class KernelModule(LinuxASEP):
	'''
	Kernel Module ASEP detection
	'''

	def detect(self) -> Boolean:

		if self.taskInfo.ppid == 2:
			return True
		else:
			return False

	def getASEPName(self) -> String:
		return "KERNEL-MODULE"


class Cron(LinuxASEP):
	'''
	Cron ASEP detection
	'''

	def detect(self) -> Boolean:

		if self.taskInfo.service == "cron.service":
			return True

		return False

	def getASEPName(self) -> String:
		return "CRON"

	
class RCLocal(LinuxASEP):
	'''
	rc.local file ASEP detection
	'''
	
	def detect(self) -> Boolean:

		if self.taskInfo.service == "rc-local.service":
			return True

		return False

	def getASEPName(self) -> String:
		return "RC-LOCAL"


class Profile(LinuxASEP):
	'''
	.profile file ASEP detection
	'''

	def detect(self) -> Boolean:

		if re.search("session-[0-9]+\.scope", self.taskInfo.service):
			return True

		return False

	def getASEPName(self) -> String:
		return "PROFILE"


class Bashrc(LinuxASEP):
	'''
	.bashrc file ASEP detection
	'''

	def detect(self) -> Boolean:

		if re.search("user@[0-9]+\.service", self.taskInfo.parentService):
			return True

		return False

	def getASEPName(self) -> String:
		return "BASHRC"


class SystemdService(LinuxASEP):
	'''
	Systemd service ASEP detection
	'''

	def detect(self) -> Boolean:

		if self.taskInfo.service != "":
			return True

		return False

	def getASEPName(self) -> String:
		return "SYSTEMD-SERVICE"




## Main class
class Linusap(plugins.PluginInterface):
	""" Finds ASEP for every process """

	_required_framework_version = (2, 0, 0)


	@classmethod
	def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
		return [
			requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
			requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
			requirements.ListRequirement(name = 'pid',
                                         description = 'Filter on specific process IDs',
                                         element_type = int,
                                         optional = True)
		]



	def generator(self, tasks):
		# Iterate over tasks to find which ASEP invoked them

		# Iterate processes
		for task in tasks:
			
			# Get task info
			taskInfo = TaskInfo(task)

			# Define all ASEP detection strategies
			detection = []
			detection.append(KernelModule(taskInfo))
			detection.append(Cron(taskInfo))
			detection.append(RCLocal(taskInfo))
			detection.append(Profile(taskInfo))
			detection.append(Bashrc(taskInfo))
			detection.append(SystemdService(taskInfo))
			

			ASEPName = "UNDEFINED"

			# Iterate over all the strategies to find the ASEP
			for strategy in detection:
				if(strategy.detect()):
					ASEPName = strategy.getASEPName()
					break
			
			# Send data as a touple
			yield (0, (taskInfo.pid, taskInfo.ppid, taskInfo.name, taskInfo.service, ASEPName))


	def run(self):
		# Run plugin
		

		# Get process list
		filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

		# Define touple
		return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str), ("SERVICE", str), ("ASEP", str)],
                                    self.generator(
                                        pslist.PsList.list_tasks(self.context,
                                                                self.config['kernel'],
                                                                filter_func = filter_func)))
