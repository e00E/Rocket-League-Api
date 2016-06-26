Install (via PIP):

`pip install git+git://github.com/e00E/Rocket-League-Api.git@master`


Example:

```
from rocket_league_api import *

session_id = cheat_login()
result = execute_commands([get_skill_leaderboard_v2('10')], session_id) # Get 1v1 leaderboard
print(result)
```
