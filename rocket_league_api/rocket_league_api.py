import requests
import logging

# This requests session is used for all requests made in this module.
# Since we query the same server over and over this can improve performance.
session = requests.Session()

# Text and links displayed in the main menu are found under this url.
cdn_url = 'https://rl-cdn.psyonix.com'

# Used to query the api.
appspot_url = 'https://psyonix-rl.appspot.com'
login_path = '/auth/'
command_path = '/callproc105/'

# There are more headers in the real client's requests but they dont seem necessary
# and I dont mind Psyonix seeing that this isnt the real client.
# The real client additionally sends:
# User-Agent: UE3-TA,UE3Ver(10897)
# Content-Type: application/x-www-form-urlencoded
appspot_headers = {
	'Cache-Control': 'no-cache',
	'Environment': 'Prod',
	}

# Hardcoded values in the real client.
# These are the same for every client afaik.
secret_key = 'dUe3SE4YsR8B0c30E6r7F2KqpZSbGiVx'
callproc_key = 'pX9pn8F4JnBpoO8Aa219QC6N7g18FJ0F'

# Converts mmr to the skill rating displayed in the leaderboards
def mmr_to_skill_rating(mmr):
	return round(mmr * 20 + 100)

# None or '' means has not even played one game in the playlist
tiers = {
	0: 'Unranked',
	1: 'Prospect I',
	2: 'Prospect II',
	3: 'Prospect III',
	4: 'Prospect Elite',
	5: 'Challenger I',
	6: 'Challenger II',
	7: 'Challenger III',
	8: 'Challenger Elite',
	9: 'Rising Star',
	10: 'Shooting Star',
	11: 'All Star',
	12: 'Superstar',
	13: 'Champion',
	14: 'Super Champion',
	15: 'Grand Champion'
}

ranked_game_types = {
	'10': '1v1',
	'11': '2v2',
	'12': '3v3 solo',
	'13': '3v3'}

leaderboard_types = {
	'wins': 'Wins',
	'goals': 'Goals',
	'mvps': 'MVPs',
	'saves': 'Saves',
	'shots': 'Shots',
	'assists': 'Assists'}



# Perform authentication to obtain a session id
# This function currently only works with some information you
# need to manually obtain from sniffing the real client's
# connection like the auth code.
# auth_code seems to be generated based at least on the
# current time and I have not reverse engineered how this
# works yet.
# player_id is the user's steam id if platform is Steam and
# likely the PSN name if platform is ps4 but I did not test that.
# build_id too is just copied from the client and seems to increment
# with updates. It recently turned negative...
# issuer_id was always 0 in my tests. As of 28-04-2016 issuer_id gets set but I dont know in what way.
def login(player_name, player_id, auth_code, secret_key=secret_key, platform='Steam', build_id='812023742', build_region='', issuer_id = '0', url=appspot_url, path=login_path):
	headers = { 'LoginSecretKey': secret_key }
	headers.update(appspot_headers)
	parameters = {
		'PlayerName': player_name,
		'PlayerID': player_id,
		'Platform': platform,
		'BuildID': build_id,
		'BuildRegion': build_region,
		'AuthCode': auth_code,
		'IssuerID': issuer_id}
	r = session.post(url + path, headers=headers, data=parameters, stream=False) #add verify=False to debug with Fiddler
	try:
		r.raise_for_status()
	except requests.exceptions.RequestException as e:
		logging.error('login encountered requests exception {}'.format(e))
		raise
	if r.content != b'1':
		if 'SessionID' in r.headers:
			logging.warning('login did not receive expected server answer, instead it received {}'.format(r.content))
		else:
			logging.error('login did not receive expected server answer and no SessionID header, instead it received {}'.format(r.content))
			raise RuntimeError( "Could not authenticate")
	return r.headers['SessionID']

# Some more info about session ids.
# If you issue any request using maybe every 5 minutes
# they seem to stay valid for around 5 hours.
# So you dont need to regenerate them too often.

# There is finally a way to get a valid session id
# without needing to understand how Psyonix' algorithm
# works. Apparently with platform set to PS4 any player
# just gets accepted as valid.
# Currently we just hardcode a player_id of 0
# and leave the rest empty.
def cheat_login():
	session_id = login('', '1', '', platform='PS4')
	return session_id

# Peforms an api request
# This function is usually used via execute_commands.
# session_id is generated from login or user provided.
def callproc(session_id, data, callproc_key=callproc_key, url=appspot_url, path=command_path):
	logging.debug('callproc called with data {}'.format(data))
	headers = {
		'SessionID': session_id,
		'CallProcKey': callproc_key }
	headers.update(appspot_headers)
	r = session.post(url + path, headers=headers, data=data) #verify=False
	logging.debug('sending raw: {}'.format(data))
	try:
		r.raise_for_status()
	except requests.exceptions.RequestException as e:
		logging.error('callproc encountered requests exception {}'.format(e))
		raise
	r.encoding = 'utf-8'
	logging.debug('callproc got data from server {}'.format(r.content))
	return r.text

# Send multiple commands to the Rocket League servers and parse the results
# commands is a list of Command.
# if parse is false the result will not be parsed.
def execute_commands(commands, session_id, callproc_key=callproc_key, parse=True):
	data = callproc(session_id, encode_commands(commands), callproc_key)
	data = data.rstrip('\r\n').split('\r\n\r\n')
	results = list()
	for i, d in enumerate(data):
		if not parse:
			results.append(d)
		else:
			if d.startswith('SQL ERROR'): #when command semantically doesnt make sense like trying to get skill of a user who doesnt exist
				raise RuntimeError('execute_commands got sql error from server')
			elif d.startswith('SCRIPT ERROR'): #when required parameters were obmitted or have the wrong form
				raise RuntimeError('execute_commands got script error from server')
			elif d.startswith('PROCEDURE ERROR'): #when trying to call a function that doesnt exist
				raise RuntimeError('execute_commands got procedure error from server')
			else:
				results.append(commands[i].parse_result(parse_keyvalues(d)))
	return results

# Turns text responses into dictioniaries of their key-values
# Returns a list of dictionaries (one for every input line).
def parse_keyvalues(response):
	# WARNING: currently usernames can contain unescaped '&' and '=' leading
	# to correct parsing being impossible in some cases.
	# I sent bug report to psyonix, only they can fix it
	logging.debug('parse_result called with data {}'.format(response.encode('utf-8')))
	parsed_keyvalues = list()
	lines = response.splitlines()
	if len(lines) == 0:
		logging.warning('parse_keyvalues got 0 lines of data')
	for line in lines:
		keyvalue_strings = line.split('&') # One string per keyvalue
		if len(keyvalue_strings) == 0:
			logging.warning('parse_keyvalues found no key-values in line {}'.format(line))
		keyvalues = dict() # All keyvalues of this line in one dictionary
		for keyvalue in keyvalue_strings:
			try:
				(key, value) = keyvalue.split('=')
				if key in keyvalues:
					logging.warning('parse_keyvalues got key {} multiple times, keeping old one'.format(key))
					continue
				value = None if value == '' else value # Turn empty string into None
				keyvalues[key] = value
			except ValueError as e:
				logging.warning('parse_keyvalues could not turn {} into a key and a value, skipping'.format(keyvalue))
				continue
		parsed_keyvalues.append(keyvalues)
	return parsed_keyvalues

# Turn a Command into text for sending to the servers
def encode_commands(commands):
	data = ''
	for i, command in enumerate(commands):
		data += '&Proc[]={}'.format(command.name)
		for parameter in command.parameters:
			data += '&P{}P[]={}'.format(i, parameter)
	return data

# Represents a command that can be sent to the server
class Command:
	def __init__(self, name, parameters=[]):
		self.name = name
		self.parameters = parameters
	def parse_result(self, data): #This is overriden by the actual commands
		return None

# Exception thrown when a Command is missing a keyvalue it requires
class MissingRequiredKeyError(Exception):
    pass

# Check if server responses roughly match what we expect
# required keys need to be in the result or an exception is thrown
# expected are supposed to be in the result but are not needed to complete parsing, a warning is issued if they are missing
# optional keys can be there but need to be, for them no warning is issued
# keys that were supplied but are in neither of the above sets are warned for too
def form_check(data, required_keys=set(), expected_keys=set(), expected_key_values=dict(), optional_keys=set()):
	#required_keys and expected keys are sets, expected_key_values is a dict
	#no key should be in more than one of the sets
	data_keys = set(data.keys())
	missing_required_keys = required_keys.difference(data_keys)
	missing_expected_keys = expected_keys.union(set(expected_key_values.keys())).difference(data_keys)
	wrong_expected_keys = set()
	unexpected_keys = (data_keys.difference(expected_keys.union(set(expected_key_values.keys())).union(required_keys))).difference(optional_keys)
	for key in set(expected_key_values.keys()).difference(missing_expected_keys):
		if expected_key_values[key] != data[key]:
			wrong_expected_keys.add(key)
	if len(missing_required_keys) > 0:
		logging.error('form_check found the following required keys to be missing {}'.format(missing_required_keys))
		raise MissingRequiredKeyError(missing_required_keys)
	got_warning = False
	if len(missing_expected_keys) > 0:
		logging.warning('form check found the following expected keys to be missing {}'.format(missing_expected_keys))
		got_warning = True
	if len(wrong_expected_keys) >  0:
		kvs = list()
		for key in wrong_expected_keys:
			kvs.append((key, expected_key_values[key], data[key]))
		logging.warning('form check found the following expected key-values to have the wrong values (Key, Expected, Observed): {}'.format(kvs))
		got_warning = True
	if len(unexpected_keys) > 0:
		logging.warning('form check found the following unexpected keys {}'.format(unexpected_keys))
		got_warning = True
	return got_warning

#Implmentations of specific commands

# Get mmr and ranked tier for a specific user
class get_skill_leaderboard_value_for_user_v2steam(Command):
	def __init__(self, steam_id, game_type):
		if game_type not in ranked_game_types:
			logging.warning('get_skill_leaderboard_value_for_user_v2steam created with unknown game_type {}'.format(game_type))
		self.game_type = game_type
		Command.__init__(self, 'GetSkillLeaderboardValueForUser_v2Steam', [steam_id, game_type])
	def parse_result(self, data):
		if len(data) != 2:
			logging.warning('get_skill_leaderboard_value_for_user_v2steam.parse_result expected data length of 2 but got {}'.format(len(data)))
		leaderboard_kv = {'LeaderboardID': 'Skill{}'.format(self.game_type)}
		form_check(data[0], required_keys=set(['Value', 'MMR']), expected_key_values=leaderboard_kv)
		form_check(data[1], expected_key_values=leaderboard_kv)
		mmr = data[0]['MMR']
		tier = data[0]['Value']
		return { 'mmr': float(mmr) if mmr != None else None, 'tier': int(tier) if tier != None else None }

class get_skill_leaderboard_value_for_user_v2ps4(Command):
	def __init__(self, steam_id, game_type):
		if game_type not in ranked_game_types:
			logging.warning('get_skill_leaderboard_value_for_user_v2ps4 created with unknown game_type {}'.format(game_type))
		self.game_type = game_type
		Command.__init__(self, 'GetSkillLeaderboardValueForUser_v2PS4', [steam_id, game_type])
	def parse_result(self, data):
		return get_skill_leaderboard_value_for_user_v2steam.parse_result(self, data)

# Get the ranked leaderboard for a playlist.
# Always returns the top 100 steam and then the top 100 playstation players
class get_skill_leaderboard_v3(Command):
	def __init__(self, game_type):
		if game_type not in ranked_game_types:
			logging.warning('get_skill_leaderboard_v2 created with unknown game_type {}'.format(game_type))
		self.game_type = game_type
		Command.__init__(self, 'GetSkillLeaderboard_v2', [game_type])
	def parse_result(self, data):
		results = []
		leaderboard_kv = {'LeaderboardID': 'Skill{}'.format(self.game_type)}
		form_check(data[0], expected_key_values=leaderboard_kv)
		for i, entry in enumerate(data[1:]):
			try:
				form_check(entry, set(['UserName', 'Value', 'MMR']), set(['Platform']), dict(), set(['SteamID']))
			except MissingRequiredKeyError:
				logging.warning('get_skill_leaderboard_v2.parse_result skipping line {} because it is missing some required keys'.format(i+1))
				continue
			result = {'name': entry['UserName'], 'mmr': float(entry['MMR']), 'tier': int(entry['Value']) if entry['Value'] != '' else None }
			if 'Platform' in entry:
				result['platform'] = entry['Platform']
				if entry['Platform'] == 'Steam':
					if 'SteamID' in entry:
						result['steam_id'] = entry['SteamID']
					else:
						logging.warning('get_skill_leaderboard_v2.parse_result platform is Steam but no SteamID in line {}'.format(i+1))
				elif entry['Platform'] == 'PSN':
					pass
				else:
					logging.warning('get_skill_leaderboard_v2.parse_result platform is neither Steam nor PSN {}'.format(i+1))
			results.append(result)
		return results

# Retrive mu, sigma, mmr, tier, matches played and division for every playlist including unranked for a user
# Division was 0 or None so far, not sure what it means
# mmr is equal to mu - 3 * sigma
class get_player_skill_steam(Command):
	def __init__(self, steamid):
		Command.__init__(self, 'GetPlayerSkillSteam', [steamid])
	def parse_result(self, data):
		results = dict()
		for entry in data:
			form_check(entry, set(['Playlist', 'Tier', 'Mu', 'Sigma', 'MatchesPlayed', 'MMR', 'Division']))
			if entry['Playlist'] in results:
				logging.warning('get_player_skill_steam.parse_result encountered playlist {} more than once, skipping'.format(entry['Playlist']))
			results[entry['Playlist']] = {
				'tier': int(entry['Tier']) if entry['Tier'] != None else None,
				'mu': float(entry['Mu']) if entry['Mu'] != None else None,
				'sigma': float(entry['Sigma']) if entry['Sigma'] != None else None,
				'matches_played': int(entry['MatchesPlayed']) if entry['MatchesPlayed'] != None else None,
				'mmr': float(entry['MMR']) if entry['MMR'] != None else None,
				'division': int(entry['Division']) if entry['Division'] else None}
		return results

class get_player_skill_ps4(Command):
	def __init__(self, name):
		Command.__init__(self, 'GetPlayerSkillPS4', [name])
	def parse_result(self, data):
		return get_player_skill_steam.parse_result(self, data)

class get_leaderboard_rank_for_users_steam(Command):
	def __init__(self, steam_ids, leaderboard_type):
		assert(len(steam_ids) <= 100);
		if leaderboard_type not in leaderboard_types.values():
			logging.warning('get_leaderboard_rank_for_users_steam created with unknown leaderboard_type {}'.format(leaderboard_type))
		self.leaderboard_type = leaderboard_type
		self.steam_ids = steam_ids
		Command.__init__(self, 'GetLeaderboardRankForUsersSteam', [leaderboard_type] + steam_ids + ['0'] * (100 - len(steam_ids))) #always needs 100 ids, which is why we fill the unused ones with zeroes
	def parse_result(self, data):
		results = {}
		leaderboard_kv = {'LeaderboardID': self.leaderboard_type}
		form_check(data[0], set(), set(), leaderboard_kv)
		for i, entry in enumerate(data[1:]):
			try:
				form_check(entry, set(['UserName', 'SteamID', 'Value']))
			except MissingRequiredKeyError:
				logging.warning('get_leaderboard_rank_for_user_steam.parse_result skipping line {} because it is missing some required keys'.format(i+1))
				continue
			if entry['SteamID'] in self.steam_ids:
				results[entry['SteamID']] = (entry['UserName'], int(entry['Value']))
			else:
				logging.warning('get_leaderboard_rank_for_user_steam.parse_result expected line {}\'s SteamID {} to be part of the requested steam ids but it isnt, skipping'.format(i+1,entry['SteamID']))
				continue
		return results
