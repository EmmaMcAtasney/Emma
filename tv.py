from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
import jwt
import datetime
from bson import ObjectId
from functools import wraps
import bcrypt
from flask_cors import CORS

tv = Flask(__name__)
CORS(tv)
client = MongoClient("mongodb://127.0.0.1:27017")
tv.config['SECRET_KEY'] = 'mysecret'
db = client.TVDB # select the database
users = db.users
episodes = db.episodes # select the collection 
blacklist = db.blacklist 

def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        #token = request.args.get('token')
        token = None
        bl_token = blacklist.find_one({"token" : token})
        if bl_token is not None:
           return make_response(jsonify({'message' : 'Token has been cancelled'}), 401)   
        return func(*args, **kwargs)

    return jwt_required_wrapper    

def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, tv.config['SECRET_KEY'])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({'message' : 'Admin access required'}), 401)
    return admin_required_wrapper    

@tv.route("/api/v1.0/episodes", methods=["GET"])
def show_all_episodes():
    page_num, page_size = 1, 10
    if request.args.get('pn'):
        page_num = int(request.args.get('pn'))
    if request.args.get('ps'):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))

    data_to_return = []
    for episode in episodes.find(
        {}, {"url": 1, "name": 1, "season": 1, "number": 1, "airdate": 1, "airtime": 1, "comment_count": 1,"comments": 1, "airstamp": 1, "runtime": 1, "image": 1, "summary": 1, "_links": 1}
        ).skip(page_start).limit(page_size):
        
        episode['_id'] = str(episode['_id']) 
        for comment in episode['comments']:
            comment['_id'] = str(comment['_id'])
        data_to_return.append(episode) 
    return make_response ( jsonify(data_to_return), 200)

@tv.route("/api/v1.0/episodes/<string:id>", methods=["GET"])
def show_one_episode(id):
    validChars = "0123456789abcdef"  
    badChars = [ char for char in id if char not in validChars ]
    if len(badChars) == 0 and len(id) == 24:
        episode = episodes.find_one(
            {'_id' : ObjectId(id)},
            {"url": 1, "name": 1, "season": 1, "number": 1, "airdate": 1, "airtime": 1, "comment_count": 1,"comments": 1, "airstamp": 1, "runtime": 1, "image": 1, "summary": 1, "_links": 1}
        )
        if episode is not None:
            episode ['_id'] = str(episode['_id'])
            for comment in episode ['comments']:
                comment['_id'] = str(comment['_id']) 
            return make_response(jsonify(episode), 200)
        else:
            return make_response(jsonify({"error": "Invalid episode ID"}), 404)
    else:
        return make_response(jsonify({"error": "Invalid episode ID"}), 404)

@tv.route("/api/v1.0/episodes", methods=["POST"])
@jwt_required
def add_episode():
    if "url" in request.form and \
        "name" in request.form and \
        "season" in request.form and \
        "number" in request.form and \
        "airdate" in request.form and \
        "airtime" in request.form and \
        "airstamp" in request.form and \
        "runtime" in request.form and \
        "image" in request.form and \
        "summary" in request.form and \
        "_links" in request.form:
        new_episode = {
            "url" : request.form["url"],
            "season" : request.form["season"],
            "airdate" : request.form["airdate"],
            "airtime": request.form["airtime"],
            "comment_count": 0,
            "comments" : [],
            "airstamp": request.form["airstamp"],
            "runtime": request.form["runtime"],
            "image": request.form["image"],
            "summary": request.form["summary"],
            "_links": request.form["_links"]
        }
        new_episode_id = episodes.insert_one(new_episode)
        new_episode_link = "http://localhost:5000/api/v1.0/episodes/" \
            + str(new_episode_id.inserted_id)
        return make_response(jsonify({"url" : new_episode_link}), 201)
    else:
        return make_response(jsonify({"error" : "Missing form data"}), 404)

@tv.route("/api/v1.0/episodes/<string:id>", methods=["PUT"])
@jwt_required
def edit_episode(id):
    if "url" in request.form and \
        "name" in request.form and \
        "season" in request.form and \
        "number" in request.form and \
        "airdate" in request.form and \
        "airtime" in request.form and \
        "airstamp" in request.form and \
        "runtime" in request.form and \
        "image" in request.form and \
        "summary" in request.form and \
        "_links"in request.form:
        result = episodes.update_one (\
            {"_id" : ObjectId(id) }, {
            "$set" : {      "url" : request.form["url"],
                            "season" : request.form["season"],
                            "airdate" : request.form["airdate"],
                            "airtime": request.form["airtime"],
                            "airstamp": request.form["airstamp"],
                            "runtime": request.form["runtime"],
                            "image": request.form["image"],
                            "summary": request.form["summary"],
                            "_links": request.form["_links"]
                           }
            })
        if result.matched_count == 1:
            edited_episode_link = \
            "http://localhost:5000/api/v1.0/episodes/" + id
            return make_response(jsonify({"url":edited_episode_link} ), 200)
        else:
            return make_response(jsonify({"error" : "Invalid episode ID"}), 404)
    else:
        return make_response(jsonify({"error" : "Missing form data"} ), 404)
       
@tv.route("/api/v1.0/episodes/<string:id>",  methods=["DELETE"])
@jwt_required
@admin_required
def delete_episode(id):
    result = episodes.delete_one(\
        {"_id" : ObjectId(id) } )
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204)
    else:
        return make_response(jsonify({"error" : "Invalid episode ID"} ), 404)

        
@tv.route("/api/v1.0/episodes/<string:bid>/comments", methods=["POST"])
@jwt_required
def add_new_comment(bid):
    if  "username" in request.form and \
        "text" in request.form and \
        "stars" in request.form:
        new_comment = {
        "_id" : ObjectId(),
        "username" : request.form["username"],
        "text" : request.form["text"],
        "stars" : request.form["stars"],
        "date" : request.form["date"],
        "votes": { 'funny':0, 'useful': 0, 'cool':0 }
        }
        episodes.update_one({"_id" : ObjectId(bid)}, {"$push" : {"comments" : new_comment} } )
        new_comment_link = "http://localhost:5000/api/v1.0/episodes/" + bid \
            + "/comments/" + str(new_comment['_id'])
        return make_response(jsonify( {"url" : new_comment_link} ), 201)
    else: 
        return make_response(jsonify ({"error" : "Missing form data"} ), 404)       

@tv.route("/api/v1.0/episodes/<string:id>/comments", methods=["GET"])
def fetch_all_comments(id):
    episode = episodes.find_one({'_id' : ObjectId(id)})
    if episode is None:
        return make_response( jsonify({"error" : "Missing form data"}), 404)
    else:
        data_to_return =  []
        episode = episodes.find_one (\
            {"_id" : ObjectId(id) }, \
            { "comments" : 1, "_id" : 0} )
        for comment in episode["comments"]:
            comment["_id"] = str(comment["_id"])
            data_to_return.append(comment)
        return make_response(jsonify( data_to_return), 200)
      
@tv.route("/api/v1.0/episodes/<bid>/comments/<rid>", methods=["GET"])
def fetch_one_comment(bid,rid):
    episode = episodes.find_one({'_id' : ObjectId(bid)})
    if episode is None:
        return make_response( jsonify({"error" : "invalid episode ID"}), 404)
    else:
        episode = episodes.find_one( \
        {"comments._id" : ObjectId(rid) }, \
        {"_id" : 0, "comments.$" : 1})
        if episode is None:
            return make_response ( jsonify({"error" : "Invalid comment ID"} ), 404)
        else:
            episode['comments'][0]['_id'] = str(episode['comments'][0]['_id']) 
            return make_response (jsonify(episode['comments'][0]), 200)

@tv.route("/api/v1.0/episodes/<bid>/comments/<rid>", methods=["PUT"])
@jwt_required
def edit_comment(bid,rid):
    episode = episodes.find_one({'_id' : ObjectId(bid)})
    if episode  is None:
        return make_response ( jsonify({"error" : "Invalid  episode ID"} ), 404)
    else:
        commentFound = False
        for comment in episode["comments"]:
            if str(comment["_id"]) == rid:
                commentFound = True
                break
        if commentFound == False:
            return make_response ( jsonify({"error" : "Invalid comment ID"} ), 404)
        else:
            edited_comment = {
            "comments.$.username" : request.form["username"],
            "comments.$.text" : request.form["text"],
            "comments.$.stars" : request.form['stars'],
            "comments.$.date" : request.form["date"]
            }
            episodes.update_one( {"comments._id" : ObjectId(rid) },{"$set": edited_comment})
            edit_comment_url = "http://localhost:5000/api/v1.0/episodes/" + bid + "/comments/" + rid
            return make_response( jsonify ({"url" : edit_comment_url} ), 200)

   
@tv.route("/api/v1.0/episodes/<bid>/comments/<rid>", methods=["DELETE"])
@jwt_required
@admin_required
def delete_comment(bid,rid):
    episode = episodes.find_one({'_id' : ObjectId(bid)})
    if episode  is None:
        return make_response ( jsonify({"error" : "Invalid  episode ID"} ), 404)
    else:
        commentFound = False
        for comment in episode ["comments"]:
            if str(comment["_id"]) == rid:
                commentFound = True
                break
        if commentFound == False:
            return make_response ( jsonify({"error" : "Invalid comment ID"} ), 404)
        else:
            episodes.update_one(\
                {"_id" : ObjectId(bid) },{"$pull" : {"comments" : { "_id" : ObjectId(rid) } } } )
            return make_response(jsonify ({}), 204)

@tv.route('/api/v1.0/login', methods=['GET'])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one({'username' :auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):
                token = jwt.encode(\
                    {'user' : auth.username, 
                        'admin' : user["admin"],
                        'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                    }, tv.config['SECRET_KEY'])
                return make_response(jsonify({'token' :token.decode('UTF-8')}), 200)
            else:
                return make_response(jsonify({'message' : 'Bad password'}), 401)
        else:
            return make_response(jsonify({'message' : 'Bad username'}), 401)
    return make_response(jsonify({'message': 'Authentication required'}), 401)

@tv.route('/api/v1.0/logout', methods=["GET"])
@jwt_required
def logout():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return make_response(jsonify( { 'message' : 'Token is missing'}), 401)
    else:
        blacklist.insert_one({"token" :token})
        return make_response(jsonify({'message' : 'Logout successful'}), 200)

if __name__ == "__main__":
    tv.run(debug=True)   