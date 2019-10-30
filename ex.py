from pwn import *
import sys
import re
import pdb
import signal
from colored import fg, attr

def init():
	global f_name
	buffer = ''
	buffer += "from pwn import *\n\n"

	buffer += "context.log_level = 'debug'\n\n"

	return buffer

def send_before_menu(p, before_menu):
	### send str before menu
	for tmp in before_menu:
		menu_content = ''
		try:
			menu_content += p.recv(timeout = 5)
			p.sendline(str(tmp))
		except:
			break
	########################

def print_menu_content(menu_content):
	length = len(menu_content[len(menu_content)/2]) + 7

	print fg(213) + attr('bold') + 'This is menu_content'.center(length, '-') + attr('reset')
	for i in range(len(menu_content)):
		first = '{0}{1}{2:<2} --> {3}'.format(fg(1), attr('bold'), i, attr('reset'))
		content = '{0}{1}{2}'.format(fg(255) + attr('bold'), menu_content[i], attr('reset'))
		print  first + content

def rename_menu_content(menu_content):
	print_menu_content(menu_content)
	print 'menu_content is very important for this program. So make sure ' + fg(1) + attr('bold')+ 'it is correct' + attr('reset')
	accept = raw_input('Do you want to change menu_content? ' + fg(155) + attr('bold') + '(y/Y)' + attr('reset')).strip()
	if accept == 'y' or accept == 'Y':
		while True:
			print_menu_content(menu_content)

			buf = '(%s%sone number%s) ' % (fg(1), attr('bold'),  attr('reset'))
			buf += '{0}{1}ex) 5{2}'.format(fg('orchid'), attr('bold'), attr('reset'))
			print 'which line do you want to delete? ' + buf
			print '%s%s-1 is complete%s' % (fg(1), attr('bold'), attr('reset'))
			line_idx = int(raw_input())
			if line_idx == -1:
				menu_content = '\n'.join(menu_content)
				return menu_content.strip()
			del menu_content[line_idx]
			print ''
	else:
		menu_content = '\n'.join(menu_content)
		return menu_content.strip()

def extract_function_name(menu_content):
	global r, r2, r3
	function_names = []
	tmps = r.findall(menu_content)
	for tmp in tmps:
		idx = r3.search(tmp).group()
		tmp = r2.sub('', tmp)
		function_name = tmp.strip().lower().split(' ')[0]
		function_names.append([str(idx), function_name])
	return function_names

def find_key(menu_content):
	return menu_content.split('\n')[-1]

def def_func(key, params, function_info, params_conditions):
	tmp = 'def ' + function_info[1] + '(' + ', '.join(params) + '):\n'	
	tmp += "	p.sendafter('" + key + "', '" + function_info[0] + "')\n\n"
	for param_condition in params_conditions:
		tmp += "	p.sendafter('" + param_condition[0] + "', str(" + param_condition[1] + "))\n"
	tmp += '\n'
	return tmp

def make_func(p, menu_content, key, function_names, before_menu):
	global r2

	p.recvuntil(key, timeout = 5)
	menu = ''

	for function_info in function_names:
		### find function params and conditions
		params = []
		params_conditions = []
		log.info('processing ' + fg(1) + attr('bold') + function_info[1] + attr('reset') + ' function')
		p.sendline(function_info[0])

		if(function_names[0] == function_info):
			p.recv(1)

		try:
			while True:
				tmp = p.recv(timeout = 5).strip()
				if menu_content in tmp:
					tmp = tmp.strip().replace(menu_content, '').strip()

					#pdb.set_trace()

					#param = r2.sub('',tmp).strip().split(' ')[-1]
					#params.append(param)
					#params_conditions.append([tmp,param])
					break

				param = r2.sub('',tmp).strip().split(' ')[-1]
				params.append(param)
				params_conditions.append([tmp,param])

				content = "plz input test param for \"" + fg(1) + attr('bold') + tmp + attr('reset') + "\""
				print content
				test = raw_input(fg(51) + attr('bold') + 'param : \x1b[1;m' + attr('reset'))
				p.sendline(str(test))
				print ''
				if p.poll() == 0:
					raise EOFError

		except EOFError, exception:
			print fg(1) + attr('bold') + 'Process is terminated' + attr('reset')
			print fg(155) + attr('bold') + 'It will be restarted' + attr('reset')
			p.close()
			p = process('./' + f_name)

			send_before_menu(p, before_menu)
			p.recvuntil(key, timeout = 5)
			p.recv(1)
			menu += def_func(key, params[:-1], function_info, params_conditions[:-1])
			continue

		menu += def_func(key, params, function_info, params_conditions)
	p.close()
	return menu

def menu_build():
	global f_name

	if(len(sys.argv) >= 3):
		before_menu = sys.argv[3:]

	p = process('./' + f_name)
	#context.log_level = "debug"
	
	send_before_menu(p, before_menu)
	menu_content = p.recv(timeout = 3).strip()
	menu_content = rename_menu_content(menu_content.split('\n'))

	function_names = extract_function_name(menu_content)

	key = find_key(menu_content)
	print "key string is : \"" + fg(155) + attr('bold') + key + "\" " + attr('reset')
	print ''
	p.close()

	### make menu funciton
	p = process('./' + f_name)
	print ''
	send_before_menu(p, before_menu)
	menu = make_func(p, menu_content, key, function_names, before_menu)
	return menu

def setup():
	global f_name
	buffer = ''

	buffer += "p = process('./" + str(f_name) + "')\n"
	buffer += "#p = remote('',)\n"
	buffer += "e = ELF('./" + str(f_name) + "')\n"
	buffer += "l = e.libc\n"
	buffer += "#l = ELF('./')\n\n"

	return buffer

def useful_plt_got():
	global f_name
	e = ELF('./' + f_name)

	buffer = ''
	useful = ['printf', 'puts', 'gets', 'open', 'read', 'write', 'malloc', 'free', 'system']
	for n, addr in e.plt.items():
		if n in useful:
			buffer += n + "_plt = " + str(hex(addr)) + '\n'

	buffer += '\n'

	for n, addr in e.got.items():
		if n in useful:
			buffer += n + "_got = " + str(hex(addr)) + '\n'

	buffer += '\n'

	return buffer

def find_p_rdi_r():
	global f_name
	r = process('/bin/bash')
	r.sendline("ROPgadget --binary " + f_name + " | grep \"pop rdi ; ret\"")
	addr = r.recvuntil(':')
	r.close()

	buffer = ''
	buffer += "p_rdi_r = " + addr[0:18]
	buffer += '\n'

	return buffer

if __name__ == '__main__':
	r = re.compile(r'[0-9]+.+\n') # function content line
	r2 = re.compile(r'[^a-zA-Z\s]+') # function name
	r3 = re.compile(r'[0-9]+') # function idx

	if len(sys.argv) < 2:
		print "usage : ex.py [filename]"
		exit()
	f_name = sys.argv[1]

	py_name = str(f_name) + '.py'
	f = open(py_name, 'w')

	content = ''
	content += init()

	### menu build
	if len(sys.argv) >= 3:
		if str(sys.argv[2]) == 'menu':
			content += menu_build()
	###############
	content += setup()

	#content += useful_plt_got()
	#useful gadget : pop rdi ; ret;
	#content += find_p_rdi_r()
	####################
	content += "pause()\n\n\n\n"
	content += "p.interactive()"

	f.write(content)
