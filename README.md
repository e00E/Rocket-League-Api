Current workflow is to run Rocket League and sniff the Session ID with Fiddler, then put it in your script like in this example:

```
session_id = 'e1fb5dccb34bb38164a3919ae1e2cfc2'
result = execute_commands([get_skill_leaderboard_v2('10')], session_id) # Get 1v1 leaderboard
print(result)
```
