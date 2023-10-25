import base64
import hashlib
import hmac
import json
import os

import requests
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
SHOPIFY_SECRET = os.environ.get('SHOPIFY_SECRET')
USER_NAME = os.environ.get('USER_NAME')
PASSWORD = os.environ.get('PASSWORD')


def verify_hmac(hmac_header, data):
    hmac_header_bytes = base64.b64decode(hmac_header)
    hmac_calculated = hmac.new(SHOPIFY_SECRET.encode('utf-8'), data, hashlib.sha256)
    return hmac.compare_digest(hmac_calculated.digest(), hmac_header_bytes)

def transform_shopify_customer_data(data):
    transformed_data = {
        'email': data['email'], 
        'first_name': data.get('first_name', ''), 
        'last_name': data.get('last_name', ''), 
        'phone': data['phone'],
        'address1': data['addresses'][0],
        'address2' : data['addresses'][1],              
    }
    if(data['notes']):
        entries = data['notes'].split('\n')
        for entry in entries:
            key, value = pair.split(': ')
            if key == 'phone_number':
                transformed_data['mobile'] = value
            if key == 'bdaymonth':
                transformed_data['BirthMonth'] = datetime.datetime.strptime(value, '%b').month
            if key == 'bdayday':
                transformed_data["BirthDay"] = value
            if key == 'anniversarymonth':
                transformed_data["AnuMonth"] = datetime.datetime.strptime(value, '%b').month
            if key == 'anniversaryday':
                transformed_data['AnuhDay'] = value
    return transformed_data

def transform_shopify_order_data(data):
    transformed_data = {
        'order_id': data['id'],
        'customer_id': data['customer_id'],
        'total_price': data['total_price'],
    }
    return transformed_data

def process_webhook(data, data_transform_function, erp_endpoint):
    transformed_data = data_transform_function(data)
    erp_url = f"{erp_endpoint}"
    print(transformed_data)
    response = requests.post(erp_url, json=transformed_data, auth=(USER_NAME, PASSWORD))
    print(response.text)
    if response.status_code != 200:
        raise Exception("ERP server error") 
    return True

def handle_webhook(webhook_type):
    hmac_header = request.headers.get('X-Shopify-Hmac-SHA256')
    request_data = request.get_data(as_text=False)

    if not verify_hmac(hmac_header, request_data):
        return jsonify({'message': 'Unauthorized request'}), 401

    shopify_data = request.get_json()

    try:
        # Define the transformations and ERP endpoints based on the webhook type
        if webhook_type == 'customer':
            data_transform_function = transform_shopify_customer_data
            erp_endpoint = 'https://api.hueb.com/HUEB/srHueb.svc/AddCustomer'
        elif webhook_type == 'order':
            data_transform_function = transform_shopify_order_data
            erp_endpoint = 'ss'
        else:
            raise ValueError("Invalid webhook type")

        process_webhook(shopify_data, data_transform_function, erp_endpoint)
        return jsonify({'message':f'{webhook_type.capitalize()} data processed successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Internal server error'}), 500


# API routes
@app.route('/webhook/customer', methods=['POST'])
def receive_customer_webhook():
    return handle_webhook('customer')

# @app.route('/webhook/order', methods=['POST'])
# def receive_order_webhook():
#     return handle_webhook('order')

@app.route('/', methods=['GET'])
def index():
    return "Shopify API"

if __name__ == "__main__":
    app.run()

