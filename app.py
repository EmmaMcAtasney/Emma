from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
import jwt
import datetime
from bson import ObjectId
from functools import wraps
import bcrypt
from flask_cors import CORS



app = Flask(__name__)
CORS(app)
client = MongoClient("mongodb://127.0.0.1:27017")
app.config['SECRET_KEY'] = 'mysecret'
db = client.bizDB # select the database
users = db.users
businesses = db.businesses # select the collection 
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

        #if 'x-access-token' in request.headers:
           # token = request.headers['x-access-token']
       # if not token:
            #return jsonify({'message' : 'Token is missing'}), 401
       # try:
            #data = jwt.decode(token, app.config['SECRET_KEY'])
       # except:
           # return jsonify({'message' : 'Token is invalid'}), 401
       # return func(*args, **kwargs)
    return jwt_required_wrapper

def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({'message' : 'Admin access required'}), 401)
    return admin_required_wrapper

@app.route("/api/v1.0/businesses", methods=["GET"])
def show_all_businesses():
    page_num, page_size = 1, 10
    if request.args.get('pn'):
        page_num = int(request.args.get('pn'))
    if request.args.get('ps'):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))


    data_to_return = []
    for business in businesses.find(
        {}, {"name": 1, "city": 1, "stars": 1, "review_count": 1, "reviews": 1 }
        ).skip(page_start).limit(page_size):
        business['_id'] = str(business['_id']) 
        for review in business['reviews']:
            review['_id'] = str(review['_id'])
        data_to_return.append(business) 
    return make_response ( jsonify(data_to_return), 200)

@app.route("/api/v1.0/businesses/<string:id>", methods=["GET"])
def show_one_business(id):
    validChars = "0123456789abcdef"  
    badChars = [ char for char in id if char not in validChars ]
    if len(badChars) == 0 and len(id) == 24:
        business = businesses.find_one(
            {'_id' : ObjectId(id)},
            {"name": 1, "city": 1, "stars": 1, "review_count": 1, "reviews": 1 }
        )
        if business is not None:
            business ['_id'] = str(business['_id'])
            for review in business ['reviews']:
                review['_id'] = str(review['_id'])
            return make_response(jsonify(business), 200)
        else:
            return make_response(jsonify({"error": "Invalid business ID"}), 404)
    else:
        return make_response(jsonify({"error": "Invalid business ID"}), 404)

@app.route("/api/v1.0/businesses", methods=["POST"])
@jwt_required
def add_business():
    if "name" in request.form and \
        "city" in request.form and \
        "stars" in request.form:
        new_business = {
            "name" : request.form["name"],
            "city" : request.form["city"],
            "stars" : request.form["stars"],
            "review_count": 0,
            "reviews" : []
        }
        new_business_id = businesses.insert_one(new_business)
        new_business_link = "http://localhost:5000/api/v1.0/businesses/" \
            + str(new_business_id.inserted_id)
        return make_response(jsonify({"url" : new_business_link}), 201)
    else:
        return make_response(jsonify({"error" : "Missing form data"}), 404)

@app.route("/api/v1.0/businesses/<string:id>", methods=["PUT"])
@jwt_required
def edit_business(id):
    if "name" in request.form and \
        "city" in request.form and \
        "stars" in request.form:
        result = businesses.update_one (\
            {"_id" : ObjectId(id) }, {
                "$set" : { "name": request.form["name"],
                           "city" : request.form["city"],
                           "stars" : request.form["stars"]
                           }
            })
        if result.matched_count == 1:
            edited_business_link = \
            "http://localhost:5000/api/v1.0/businesses/" + id
            return make_response(jsonify({"url":edited_business_link} ), 200)
        else:
            return make_response(jsonify({"error" : "Invalid business ID"}), 404)
    else:
        return make_response(jsonify({"error" : "Missing form data"} ), 404)

@app.route("/api/v1.0/businesses/<string:id>",  methods=["DELETE"])
@jwt_required
@admin_required
def delete_business(id):
    result = businesses.delete_one(\
        {"_id" : ObjectId(id) } )
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204)
    else:
        return make_response(jsonify({"error" : "Invalid business ID"} ), 404)

@app.route("/api/v1.0/businesses/<string:bid>/reviews", methods=["POST"])
def add_new_review(bid):
    if  "username" in request.form and \
        "text" in request.form and \
        "stars" in request.form:
        new_review = {
        "_id" : ObjectId(),
        "username" : request.form["username"],
        "text" : request.form["text"],
        "stars" : request.form["stars"],
        "date" : request.form["date"],
        "votes": { 'funny':0, 'useful': 0, 'cool':0 }
        }
        businesses.update_one({"_id" : ObjectId(bid)}, {"$push" : {"reviews" : new_review} } )
        new_review_link = "http://localhost:5000/api/v1.0/businesses/" + bid \
            + "/reviews/" + str(new_review['_id'])
        return make_response(jsonify( {"url" : new_review_link} ), 201)
    else: 
        return make_response(jsonify ({"error" : "Missing form data"} ), 404)

@app.route("/api/v1.0/businesses/<string:id>/reviews", methods=["GET"])
def fetch_all_reviews(id):
    business = businesses.find_one({'_id' : ObjectId(id)})
    if business is None:
        return make_response( jsonify({"error" : "Missing form data"}), 404)
    else:
        data_to_return =  []
        business = businesses.find_one (\
            {"_id" : ObjectId(id) }, \
            { "reviews" : 1, "_id" : 0} )
        for review in business["reviews"]:
            review["_id"] = str(review["_id"])
            data_to_return.append(review)
        return make_response(jsonify( data_to_return), 200)

@app.route("/api/v1.0/businesses/<bid>/reviews/<rid>", methods=["GET"])
def fetch_one_review(bid,rid):
    business = businesses.find_one({'_id' : ObjectId(bid)})
    if business is None:
        return make_response( jsonify({"error" : "invalid business ID"}), 404)
    else:
        business = businesses.find_one( \
        {"reviews._id" : ObjectId(rid) }, \
        {"_id" : 0, "reviews.$" : 1})
        if business is None:
            return make_response ( jsonify({"error" : "Invalid review ID"} ), 404)
        else:
            business['reviews'][0]['_id'] = str(business['reviews'][0]['_id']) 
            return make_response (jsonify(business['reviews'][0]), 200)

@app.route("/api/v1.0/businesses/<bid>/reviews/<rid>", methods=["PUT"])
@jwt_required
def edit_review(bid,rid):
    business = businesses.find_one({'_id' : ObjectId(bid)})
    if business  is None:
        return make_response ( jsonify({"error" : "Invalid  busisiness ID"} ), 404)
    else:
        reviewFound = False
        for review in business["reviews"]:
            if str(review["_id"]) == rid:
                reviewFound = True
                break
        if reviewFound == False:
            return make_response ( jsonify({"error" : "Invalid review ID"} ), 404)
        else:
            edited_review = {
            "reviews.$.username" : request.form["username"],
            "reviews.$.text" : request.form["text"],
            "reviews.$.stars" : request.form['stars'],
            "reviews.$.date" : request.form["date"]
            }
            businesses.update_one( {"reviews._id" : ObjectId(rid) },{"$set": edited_review})
            edit_review_url = "http://localhost:5000/api/v1.0/businesses/" + bid + "/reviews/" + rid
            return make_response( jsonify ({"url" : edit_review_url} ), 200)

@app.route("/api/v1.0/businesses/<bid>/reviews/<id>", methods=["DELETE"])
@jwt_required
@admin_required
def delete_review(bid,rid):
    business = businesses.find_one({'_id' : ObjectId(bid)})
    if business  is None:
        return make_response ( jsonify({"error" : "Invalid  busisiness ID"} ), 404)
    else:
        reviewFound = False
        for review in business ["reviews"]:
            if str(review["_id"]) == rid:
                reviewFound = True
                break
        if reviewFound == False:
            return make_response ( jsonify({"error" : "Invalid review ID"} ), 404)
        else:
            businesses.update_one(\
                {"_id" : ObjectId(bid) },{"$pull" : {"reviews" : { "_id" : ObjectId(rid) } } } )
            return make_response(jsonify ({}), 204)

@app.route('/api/v1.0/login', methods=['GET'])
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
                    }, app.config['SECRET_KEY'])
                return make_response(jsonify({'token' :token.decode('UTF-8')}), 200)
            else:
                return make_response(jsonify({'message' : 'Bad password'}), 401)
        else:
            return make_response(jsonify({'message' : 'Bad username'}), 401)
    return make_response(jsonify({'message': 'Authentication required'}), 401)
   
    # if auth and auth.password == 'password':
    #     token = jwt.encode(\
    #         {'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, \
    #         app.config['SECRET_KEY'])
    #     return make_response jsonify ({'token' : token.decode('UTF-8')})
    # return make_response('Could not verify',401, {'WWW-Authenticate' : 'Basic realm = "Login required'})
    
@app.route('/api/v1.0/logout', methods=["GET"])
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
    app.run(debug=True)