from flask import request, jsonify, abort,render_template,url_for,send_file,send_from_directory
from Shared import app, bcrypt, db,socketio,jwt,push_service
from flask_login import login_user, current_user, logout_user, login_required
from flask_login import login_user, current_user, logout_user, login_required
from Shared.models import User, Group, SharedPics
from werkzeug import secure_filename
from flask_socketio import join_room, leave_room,send,emit
import shutil
from PIL import Image
import os
from flask_jwt_extended import (
    jwt_required, get_jwt_identity,
    create_access_token, get_raw_jwt
)

blacklist = set()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist
# Create some test data for our catalog in the form of a list of dictionaries.
books = [
    {'id': 0,
     'title': 'A Fire Upon the Deep',
     'author': 'Vernor Vinge',
     'first_sentence': 'The coldsleep itself was dreamless.',
     'year_published': '1992'},
    {'id': 1,
     'title': 'The Ones Who Walk Away From Omelas',
     'author': 'Ursula K. Le Guin',
     'first_sentence': 'With a clamor of bells that set the swallows soaring, the Festival of Summer came to the city Omelas, bright-towered by the sea.',
     'published': '1973'},
    {'id': 2,
     'title': 'Dhalgren',
     'author': 'Samuel R. Delany',
     'first_sentence': 'to wound the autumnal city.',
     'published': '1975'}
]
'''
group_clients={}
nearby_clients={}
'''

@app.route('/')
def home():
    registration_id = "dBEYRb0XjVM:APA91bHRVO8Im0pmqcbWZte5fedK7YtExibhS4mS2d-r4ZXLGg_qt2lvZhGyW1e0I-iWCfW4wJf4p0M5LSfRfsmh9XmqLKVkb6Zm3zJsJLKGkBXyj1_7em7l3rPUdDa05oU33PeBtyQt"
    message_title = "Uber update"
    message_body = "Hi john, your customized news for today is ready"
    result = push_service.notify_single_device(registration_id=registration_id, message_title=message_title, message_body=message_body)
    print(result)
    return "nothing"


@app.route('/get_groups')
def sessions():
    return render_template('session.html')

@socketio.on('connected')
def handle_connected_groups(json, methods=['GET', 'POST']):
    print('connected: ' + str(json))
'''
@socketio.on('connected',namespace='/nearby')
def handle_connected_nearby(json, methods=['GET', 'POST']):
    print('connected: ' + str(json))
    nearby_clients[json['id']]=request.sid
    print('nearby_clients: ' + str(nearby_clients))
'''

def handle_group_full_delete(members):
    for member in members:
        group_obj=[]
        for group in member.groups:
            group_obj.append({"id":group.id,"name":group.name})
            '''
            members=[]
            for member1 in group.members:
                members.append({"name":member1.name})
            group_obj.append({"id":group.id,"name":group.name,"members": members })
            '''
        namespace='/groups/'+member.id
        print(namespace)      
        socketio.emit('my response', group_obj,namespace=namespace)


def handle_group_admin_delete(members,admin_ref,name):
    message_title = "Shared Groups"
    message_body ="You are the new admin of group "+str(name)
    registration_id = admin_ref.token
    result = push_service.notify_single_device(registration_id=registration_id, message_title=message_title, message_body=message_body)
    print(result)
    for member in members:
        group_obj=[]
        for group in member.groups:
            group_obj.append({"id":group.id,"name":group.name})
            '''
            members=[]
            for member1 in group.members:
                members.append({"name":member1.name})
            group_obj.append({"id":group.id,"name":group.name,"members": members })
            '''
        namespace='/groups/'+member.id
        print(namespace)      
        socketio.emit('my response', group_obj,namespace=namespace)

def handle_group_created(admin,members,name,admin_id):
    message_title = "Added to group"
    message_body = str(admin)+" added you to group "+str(name)
    registration_ids=[]
    for member in members:
        if(member.id!=admin_id):
            registration_ids.append(member.token)
        group_obj=[]
        for group in member.groups:
            group_obj.append({"id":group.id,"name":group.name})
            '''
            members=[]
            for member1 in group.members:
                members.append({"name":member1.name})
            group_obj.append({"id":group.id,"name":group.name,"members": members })
            '''
        namespace='/groups/'+member.id
        print(namespace)      
        socketio.emit('my response', group_obj,namespace=namespace)
    result = push_service.notify_multiple_devices(registration_ids=registration_ids, message_title=message_title, message_body=message_body)
    print (result)

def handle_group_deleted(admin,members,name):
    message_title = "Shared Groups"
    message_body = str(admin)+" removed you from group "+str(name)
    registration_ids=[]
    for member in members:
       # user=User.query.get(member.id)
       # groups=user.groups
        registration_ids.append(member.token)
        group_obj=[]
        for group in member.groups:
            group_obj.append({"id":group.id,"name":group.name})
            '''
            members=[]
            for member1 in group.members:
                members.append({"name":member1.name})
            group_obj.append({"id":group.id,"name":group.name,"members": members })
            '''
        namespace='/groups/'+member.id
        print(namespace)      
        socketio.emit('my response', group_obj,namespace=namespace)
    result = push_service.notify_multiple_devices(registration_ids=registration_ids, message_title=message_title, message_body=message_body)
    print (result)

def handle_group_listen(group):
    members=[]
    for member in group.members:
        members.append({"name":member.name,"id":member.id,"email":member.email})
    group_obj=({"id":group.id,"name":group.name,"members":members,"admin":group.admin })
    #for member in group.members:
    namespace='/groups/'+str(group.id)
    socketio.emit('my response3', group_obj,namespace=namespace)


@app.route("/group/get_group", methods=['POST','GET'])
@jwt_required
def get_group_info():
    json=request.get_json()
    group=Group.query.get(json['group_id'])
    group_obj={}
    members=[]
    for member in group.members:
        members.append({"name":member.name,"id":member.id,"email":member.email})
    group_obj=({"id":group.id,"name":group.name,"members":members,"admin":group.admin })
    return jsonify(group_obj)


@app.route("/group/add_members", methods=['POST','GET'])
@jwt_required
def group_add_members():
    dict_body=request.get_json()
    group_id=dict_body['group_id']
    member_ids=dict_body['member_ids']
    group=Group.query.get(group_id)
    new_members=[]
    for member_id in member_ids:
        member = User.query.get(member_id)
        if member:
            group.members.append(member)
            new_members.append(member)  
    db.session.commit()
    handle_group_listen(group)
    handle_group_created(group.admin_ref.user_id,new_members,group.name,group.admin_ref.admin_id)
    return jsonify({'message': 'Added to Group.'}), 200


@app.route("/group/add", methods=['POST','GET'])
@jwt_required
def make_new_group():
    dict_body=request.get_json()
    # admin,name,members
    admin=dict_body['id']
    name=dict_body['name']
    member_ids=dict_body['member_ids']
    user = User.query.get(admin)
    if(user):
        group=Group(admin=admin,name=name) 
        group.members.append(user)
        for member_id in member_ids:
            member = User.query.get(member_id)
            if member:
                group.members.append(member)
        db.session.add(group)
        db.session.commit()
        os.makedirs(app.root_path+'/protected/shared_pics/'+str(group.id)+'/thumb')
        handle_group_created(user.user_id,group.members,group.name,admin)
        return jsonify({'message': 'Created Group.'}), 200
    else:
        return jsonify({'message': 'User Not Found.'}), 403

@app.route("/group/remove", methods=['POST','GET'])
@jwt_required
def remove_user():
    dict_body=request.get_json()
    # admin,name,members
    user_id=dict_body['user_id']
    group_id=dict_body['group_id']
    user = User.query.get(user_id)
    if(user):
        group=Group.query.get(group_id)
        print(group)
        if(len(group.members)==1):
            del_us=group.members[0]
            group.members=[]
            g_id=str(group.id)
            for pic in group.shared_pics:
                db.session.delete(pic)
            db.session.delete(group)
            db.session.commit()
            handle_group_full_delete([del_us])
            handle_group_listen(group)
            shutil.rmtree(app.root_path+'/protected/shared_pics/'+g_id)
            return jsonify({'message': 'Deleted Full Group.'}), 200
        for i in range(len(group.members)):
            if(group.members[i].id==user.id):
                    deleted_user=group.members.pop(i)
                    break
        print(deleted_user)
        if(deleted_user.id==group.admin):
            new_admin=group.members[0].id
            group.admin=new_admin
            db.session.commit()
            handle_group_admin_delete([deleted_user],group.admin_ref,group.name)
            handle_group_listen(group)
            return jsonify({'message': 'Deleted and made new admin.'}), 200
        db.session.commit()
        handle_group_deleted(group.admin_ref.user_id,[deleted_user],group.name)
        handle_group_listen(group)
        return jsonify({'message': 'Removed from Group.'}), 200

        '''
        handle_group_created(admin,group)
        '''
        return jsonify({'message': 'Created Group.'}), 200
    else:
        return jsonify({'message': 'User Not Found.'}), 403

@app.route("/group/get", methods=['POST','GET'])
@jwt_required
def get_groups():
    json=request.get_json()
    user=User.query.get(json['id'])
    groups=user.groups
    group_obj=[]
    for group in groups:
        '''
        members=[]
        for member in group.members:
            members.append({"name":member.name})
        '''
        group_obj.append({"id":group.id,"name":group.name })
    return jsonify(group_obj)



def handle_neary_users(users):
    if (len(users)>0):
        for user in users:
            
            user_arr=[]
            users_new=User.query.filter((User.latitude>=(float(user.latitude)-.002)) & (User.latitude<=(float(user.latitude)+.002)) & (User.longitude<=(float(user.longitude)+.002)) & (User.longitude>=(float(user.longitude)-.002)) & (User.id!=user.id)).all()
            for user_new in users_new:
                user_arr.append({"user_id":user_new.id,"user_name":user_new.name ,"user_email":user_new.email,"last_seen":user_new.last_seen})        
            namespace='/nearby/'+user.id
            socketio.emit('my response2', user_arr,namespace=namespace)


@app.route("/user/location", methods=['POST'])
@jwt_required
def location_update():
    dict_body = request.get_json()
    user = User.query.get(dict_body['id'])
    if(user):
        old_users=User.query.filter((User.latitude>=(float(user.latitude)-.002)) & (User.latitude<=(float(user.latitude)+.002)) & (User.longitude<=(float(user.longitude)+.002)) & (User.longitude>=(float(user.longitude)-.002))& (User.id!=user.id)).all()        
        user.latitude = dict_body['latitude']
        user.longitude = dict_body['longitude']
        user.last_seen = dict_body['last_seen']
        db.session.commit()
        users=User.query.filter((User.latitude>=(float(user.latitude)-.002)) & (User.latitude<=(float(user.latitude)+.002)) & (User.longitude<=(float(user.longitude)+.002)) & (User.longitude>=(float(user.longitude)-.002))).all()
        users=users+old_users
        users=(list(dict.fromkeys(users)))
        print("now sending to ")
        print(users)
        handle_neary_users(users)
        return jsonify({'message': 'Updated Location.'}), 200
    else:
        return jsonify({'message': 'User Not Found.'}), 403

@app.route("/near_users/get", methods=['POST','GET'])
@jwt_required
def get_near_users():
    json=request.get_json()
    id=json['id']
    lat=json['lat']
    longi=json['long']
    user_arr=[]
    users=User.query.filter((User.latitude>=(float(lat)-.002)) & (User.latitude<=(float(lat)+.002)) & (User.longitude<=(float(longi)+.002)) & (User.longitude>=(float(longi)-.002)) & (User.id!=id)).all()
    for user in users:
        user_arr.append({"user_id":user.id,"user_name":user.name,"user_email":user.email,"last_seen":user.last_seen}), 200
    return jsonify(user_arr)



@app.route("/user", methods=['POST'])
def register():
    dict_body = request.get_json()
  #  if current_user.is_authenticated:
  #      return jsonify({'message': 'Already Logged In.'}), 204
    user = User.query.filter_by(email=dict_body['email'].lower()).first()
    if(user):
        if(bcrypt.check_password_hash(user.password, dict_body['password'])):
            user.token = dict_body['token']
            db.session.commit()
            ret = {
                'access_token': create_access_token(identity=user.id),
            }
            return jsonify(ret), 200
        else:
            return jsonify({'message': 'Incorrect credentials'}), 403
    else:
        hashed_password = bcrypt.generate_password_hash(
            dict_body['password']).decode('utf-8')
        user = User(id=dict_body['id'], name=dict_body['name'],
                    email=dict_body['email'].lower(), password=hashed_password, token=dict_body['token'], sharing_with=dict_body['sharing_with'],latitude=0,longitude=0)
        db.session.add(user)
        db.session.commit()
        ret = {
                'access_token': create_access_token(identity=user.id),
            }
        return jsonify(ret), 200




@app.route("/user/user_id", methods=['POST'])
@jwt_required
def user_id_set():
    dict_body = request.get_json()
    user = User.query.get(dict_body['id'])
    if(user):
        user.user_id = dict_body['user_id']
        db.session.commit()
        return jsonify({'new_id': dict_body['user_id']}), 200
    else:
        return jsonify({'message': 'User Not Found.'}), 403



@app.route("/user/get_far_user", methods=['POST'])
@jwt_required
def get_far_users():
    dict_body = request.get_json()
    user = User.query.filter_by(email=dict_body['email'].lower()).first()
    if(user):
        return jsonify({"user_id":user.id,"user_name":user.name,"user_email":user.email,"last_seen":user.last_seen}), 200
    else:
        return jsonify({'message': 'User Not Found.'}), 403


@app.route("/user/user_token", methods=['POST'])
@jwt_required
def user_token_set():
    dict_body = request.get_json()
    user = User.query.get(dict_body['id'])
    if(user):
        user.token = dict_body['token']
        db.session.commit()
        return jsonify({'message': 'Updated Token.'}), 200
    else:
        return jsonify({'message': 'User Not Found.'}), 403



@app.route("/get_pic/<pic_path>", methods=['GET'])
@jwt_required
def send_pic_url(pic_path):
    pic_path=pic_path.replace('-','/')
    return send_file(pic_path, mimetype='image/jpeg')

@app.route("/get_pics", methods=['POST','GET'])
@jwt_required
def get_pics():
    dict_body=request.get_json()
    group_id=dict_body['group_id']
    group=Group.query.get(int(group_id))
    response=[]
    for pic in group.shared_pics:
        sharer=pic.sharer
        pic_url="http://13.127.52.161:8080/get_pic/"+pic.picture
        thumb_url="http://13.127.52.161:8080/get_pic/"+pic.thumb
        response.append({"pic_id":pic.id, "pic_url":pic_url,"thumb_url":thumb_url,"sharer":sharer})
    return jsonify(response)

@app.route("/delete_pic", methods=['POST','GET'])
@jwt_required
def delete_pic():
    dict_body=request.get_json()
    pic_id=dict_body['pic_id']
    pic=SharedPics.query.get(int(pic_id))
    group=pic.group_ref
    os.remove(app.root_path.replace('\\','/')+'/'+pic.picture.replace('-','/'))
    os.remove(app.root_path.replace('\\','/')+'/'+pic.thumb.replace('-','/'))
    db.session.delete(pic)
    db.session.commit()
    handle_delete_pic(group)
    return jsonify({'message': 'Done.'}),200

def handle_delete_pic(group_ref):
    response=[]
    for pic in group_ref.shared_pics:
        sharer=pic.sharer
        pic_url="http://13.127.52.161:8080/get_pic/"+pic.picture
        thumb_url="http://13.127.52.161:8080/get_pic/"+pic.thumb
        response.append({"pic_id":pic.id, "pic_url":pic_url,"thumb_url":thumb_url,"sharer":sharer})
    namespace='/pics/'+str(group_ref.id)
    socketio.emit('uploaded',response,namespace=namespace)
    
def handle_new_pic(pic_ref):
    message_title = "Shared pics"
    message_body = str(pic_ref.sharer_ref.user_id)+" added a pic to group "+str(pic_ref.group_ref.name)
    registration_ids=[]
    for member in pic_ref.group_ref.members:
        registration_ids.append(member.token)
    response=[]
    for pic in pic_ref.group_ref.shared_pics:
        sharer=pic.sharer
        pic_url="http://13.127.52.161:8080/get_pic/"+pic.picture
        thumb_url="http://13.127.52.161:8080/get_pic/"+pic.thumb
        response.append({"pic_id":pic.id, "pic_url":pic_url,"thumb_url":thumb_url,"sharer":sharer})
    namespace='/pics/'+str(pic_ref.group_ref.id)
    socketio.emit('uploaded',response,namespace=namespace)
    result = push_service.notify_multiple_devices(registration_ids=registration_ids, message_title=message_title, message_body=message_body)
    print (result)

@app.route("/upload_pic", methods=['POST','GET'])
@jwt_required
def user_upload_pic():
    f = request.files['file']
    group_id=(request.form['group'])
    sharer=(request.form['uid'])
    picture_path=os.path.join(app.root_path,'protected/shared_pics/'+group_id,secure_filename(f.filename))
    f.save(picture_path)
    thumb_picture_path=os.path.join(app.root_path,'protected/shared_pics/'+group_id+'/thumb',secure_filename(f.filename))
    output_size=(125,125)
    i=Image.open(f)
    i.thumbnail(output_size) 
    i.save(thumb_picture_path)
    pic_path='protected-shared_pics-'+group_id+'-'+secure_filename(f.filename)
    thumb_path='protected-shared_pics-'+group_id+'-thumb-'+secure_filename(f.filename)
    pic=SharedPics(picture=pic_path,thumb=thumb_path,group=group_id,sharer=sharer)
    db.session.add(pic)
    db.session.commit()
    handle_new_pic(pic)
    
  #  socketio.emit('uploaded')
    return jsonify({'message': 'Done.'}), 200



# A route to return all of the available entries in our catalog.
@app.route('/api/v1/resources/books/all', methods=['GET'])
@jwt_required
def api_all():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200



@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200



@app.route('/api/v1/resources/books/<int:task_id>', methods=['GET'])
def get_task(task_id):
    task = [task for task in books if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    return jsonify({'task': task[0]})

