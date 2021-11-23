from github import Github
from pyngrok import ngrok
from cloudlink import CloudLink
import time

# POINT TO FILE(S) CONTAINING PLAINTEXT TOKENS
GITHUB_ACCESS_TOKEN = str(open("github_access_token").read())
NGROK_ACCESS_TOKEN = str(open("ngrok_access_token").read())
# ENABLE ONLINE MODE?
ENABLE_ONLINE = True

# SPECIFY CLOUDLINK PORT
PORT = 3000
# SPECIFY BOT NAME (Will be GitHub'd as (name).txt in root of main)
BOT_NAME = "dummy"
# SPECIFY Message Of The Day
MOTD = {
    "enable": False,
    "val": ""
}

def run_http_tunnel():
    global http_tunnel_str
    http_tunnel = ngrok.connect(PORT)
    http_tunnel_str = (str(http_tunnel).replace('NgrokTunnel: "http://','').replace('")','')).replace('" -> "http://localhost:'+str(PORT)+'"','').replace('")','')
    print("HTTP Port", str(PORT), "is open:", http_tunnel_str)

def update_serverbot_contents(content, comment):
    repo = g.get_user().get_repo("serverbots")
    all_files = []
    contents = repo.get_contents("")
    while contents:
        file_content = contents.pop(0)
        if file_content.type == "dir":
            contents.extend(repo.get_contents(file_content.path))
        else:
            file = file_content
            all_files.append(str(file).replace('ContentFile(path="','').replace('")',''))

    # Upload to github
    git_file = (str(BOT_NAME) + '.txt')
    if git_file in all_files:
        contents = repo.get_contents(git_file)
        repo.update_file(contents.path, comment, content, contents.sha, branch="main")
        print("Github file " + git_file + ' updated.')
    else:
        repo.create_file(git_file, comment, content, branch="main")
        print("Github file " + git_file + ' created.')

if __name__ == "__main__":
    # Instanciate CloudLink
    cl = CloudLink()
    if ENABLE_ONLINE:
        print("[ i ] Online mode!")
        # Authenticate GitHub with Access Token
        g = Github(GITHUB_ACCESS_TOKEN)

        # Authenticate ngrok with Access Token
        ngrok.set_auth_token(NGROK_ACCESS_TOKEN)
        
        http_tunnel_str = ""
        run_http_tunnel()
        update_serverbot_contents(str("wss://"+http_tunnel_str), "Server started on local port {0}".format(PORT))
    try:
        cl.host(PORT)
        if MOTD["enable"]:
            cl.setMOTD(MOTD["val"])
        print("Press CTRL+C to exit.")
        while cl.mode == 1:
            time.sleep(0.001)
    except KeyboardInterrupt:
        cl.stop()
    time.sleep(1)
    if ENABLE_ONLINE:
        ngrok.kill()
        update_serverbot_contents("E:SERVER_OFFLINE", "Server terminated by CTRL+C")
    print("Exiting now...")
