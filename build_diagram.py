#!/usr/bin/python

import sys
import json
import known_libs

sys.path.append('../androguard')
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *

consider_library_classes = False

framework_api = json.loads(open('api.json', 'r').read())

def isLibraryClass(classname):
	package_method = False
	for package in known_libs.known_libs:
		package_name = "L" + package + "/"
		package_name = package_name.replace(".", "/")
		if package_name in classname:
			package_method = True
			break
	return package_method

if (len(sys.argv) > 1):
	package_name = sys.argv[1]
else:
	print 'Usage:'
	print sys.argv[0], 'apkfile'
	sys.exit()

try:
	a = APK(package_name)
	d = dvm.DalvikVMFormat( a.get_dex() )
except:
	print 'Failed to decompile app'
	sys.exit()

string_method_map = {}
string_class_map = {}
method_class_map = {}

for cl in d.get_classes():
	string_class_map[cl.get_name()] = cl
	for method in cl.get_methods():
		method_class_map[method] = cl
		name = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
		string_method_map[name] = method
		if method.get_name() == "<init>": #Init is separated to provide simple getting of constructors 
			if method.get_class_name() + "->" + method.get_name() in string_method_map:
				string_method_map[method.get_class_name() + "->" + method.get_name()].append(method)
			else:
				string_method_map[method.get_class_name() + "->" + method.get_name()] = [method]

cl_links_inner = {}
cl_links_aggregate = {}
cl_links_composite = {}


for cl in d.get_classes():
	if not consider_library_classes and isLibraryClass(cl.get_name()):
		continue
	if '$' in cl.get_name():
		cl_full_name = cl.get_name()[:-1]
		splitted_name = cl.get_name()[:-1].split('$')
		for i in range(0, len(splitted_name) - 1):
			cl_name = '$'.join(splitted_name[0 : i + 1]) + ';'
			cl_inner_name = '$'.join(splitted_name[0 : i + 2]) + ';'
			if not cl_name in cl_links_inner:
				cl_links_inner[cl_name] = []
			if not cl_inner_name in cl_links_inner[cl_name]:
				cl_links_inner[cl_name].append(cl_inner_name)
	for field in cl.get_fields():
		field_class = field.get_descriptor()
		if '[' in field_class:
			field_class_before = field_class
			field_class = field_class.split('[')[-1]
			if field_class in string_class_map:
				if not cl.get_name() in cl_links_composite:
					cl_links_composite[cl.get_name()] = []
				if not field_class in cl_links_composite[cl.get_name()]:
					cl_links_composite[cl.get_name()].append(field_class)
		else:
			if field_class in string_class_map:
				if field_class in cl_links_inner and cl.get_name() in cl_links_inner[field_class]:
					continue #Hack to avoid fields being actually outer class pointers
				if not cl.get_name() in cl_links_aggregate:
					cl_links_aggregate[cl.get_name()] = []
				if not field_class in cl_links_aggregate[cl.get_name()]:
					cl_links_aggregate[cl.get_name()].append(field_class)

cl_links_inherit = {}

for cl in d.get_classes():
	if not consider_library_classes and isLibraryClass(cl.get_name()):
		continue
	cl_p = cl
	while cl_p.get_superclassname() != cl_p.get_name():
		if not cl_p.get_superclassname() in framework_api:
			if not cl_p.get_superclassname() in cl_links_inherit:
				cl_links_inherit[cl_p.get_superclassname()] = []
			cl_links_inherit[cl_p.get_superclassname()].append(cl.get_name())
		if cl_p.get_superclassname() in string_class_map:
			cl_p = string_class_map[cl_p.get_superclassname()]
		else:
			break

cl_links_utilize = {}
for cl in d.get_classes():
	if not consider_library_classes and isLibraryClass(cl.get_name()):
		continue
	for method in cl.get_methods():
		for ins in method.get_instructions():
			if "invoke" in ins.get_name():
				call_method = ""
				matchObj = re.match( r'.*, ([^,]*)', ins.get_output(), re.M|re.I)
				if (matchObj):
					call_method = matchObj.group(1)
					if call_method[:1] == '[':
						call_method = call_method[1:]
				if call_method != "":
					invoked_class = call_method.split('->')[0]
					if not invoked_class in string_class_map:
						continue
					if invoked_class == cl.get_name():
						continue
					if invoked_class in cl_links_inherit and cl.get_name() in cl_links_inherit[invoked_class]:
						continue
					if cl.get_name() in cl_links_composite and invoked_class in cl_links_composite[cl.get_name()]:
						continue
					if cl.get_name() in cl_links_aggregate and invoked_class in cl_links_aggregate[cl.get_name()]:
						continue
					if not cl.get_name() in cl_links_utilize:
						cl_links_utilize[cl.get_name()] = []
					if not invoked_class in cl_links_utilize[cl.get_name()]:
						cl_links_utilize[cl.get_name()].append(invoked_class)

#Building diagram
f_diag = open('text-diagram.txt', 'w')
f_diag.write('@startuml\n')
for cl in cl_links_inherit:
	cl_print = cl[1:].replace('/', '.').replace(';', '')
	for cl_child in cl_links_inherit[cl]:
		cl_child_print = cl_child[1:].replace('/', '.').replace(';', '')
		f_diag.write(cl_print + ' <|-- ' + cl_child_print + '\n')

for cl in cl_links_composite:
	cl_print = cl[1:].replace('/', '.').replace(';', '')
	for cl_inner in cl_links_composite[cl]:
		cl_inner_print = cl_inner[1:].replace('/', '.').replace(';', '')
		f_diag.write(cl_print + ' *-- ' + cl_inner_print + '\n')

for cl in cl_links_aggregate:
	cl_print = cl[1:].replace('/', '.').replace(';', '')
	for cl_inner in cl_links_aggregate[cl]:
		cl_inner_print = cl_inner[1:].replace('/', '.').replace(';', '')
		f_diag.write(cl_print + ' o-- ' + cl_inner_print + '\n')

for cl in cl_links_utilize:
	cl_print = cl[1:].replace('/', '.').replace(';', '')
	for cl_dep in cl_links_utilize[cl]:
		cl_dep_print = cl_dep[1:].replace('/', '.').replace(';', '')
		if cl_dep in cl_links_utilize and cl in cl_links_utilize[cl_dep]:
			f_diag.write(cl_print + ' .. ' + cl_dep_print + '\n')
			cl_links_utilize[cl_dep].remove(cl)
		else:
			f_diag.write(cl_print + ' ..> ' + cl_dep_print + '\n')
f_diag.write('@enduml\n')
f_diag.close()

print 'Saved class diagram to text-diagram.txt'
