class banner():
	def __init__(self):
		self.width = 100

	def banner_sl(self, text, ch='='):
		width=self.width
		spaced_text = ' %s ' % text
		banner = spaced_text.center(width, ch)
		return banner

	def banner_sl_box(self, text):
		width=self.width
		stars = '*' * width
		pad = (width + len(text)) // 2
		return '{0}\n{1:>{2}}\n{0}'.format(stars, text, pad)

	def banner_sl_box_open(self, text):
		width=self.width
		stars = '*' * width
		pad = (width + len(text)) // 2
		return '{0}\n{1:>{2}}'.format(stars, text, pad)

	def banner_sl_box_addline(self, text):
		width=self.width
		stars = '*' * width
		pad = (width + len(text)) // 2
		return '{1:>{2}}'.format(stars,text,pad)

	def banner_sl_box_close(self):
		width=self.width
		stars = '*' * width
		return '{0}'.format(stars)



class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'        