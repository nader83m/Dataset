#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jul 14 10:00:58 2020

@author: nadir
"""

from __future__ import print_function
import pandas as pd
import numpy as np
from sklearn import preprocessing
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from keras.models import Model
import keras
from keras.utils import np_utils
import tensorflow as tf
from numpy.random import seed


DANMINI_DOORBELL = 'Danmini_Doorbell'
ECOBEE_THERMOSTAT = 'Ecobee_Thermostat'
ENNIO_DOORBELL = 'Ennio_Doorbell'
PHILIPS_B120N10_BABY_MONITOR = 'Philips_B120N10_Baby_Monitor'
PROVISION_PT_737E_SECURITY_CAMERA = 'Provision_PT_737E_Security_Camera'
PROVISION_PT_838_SECURITY_CAMERA = 'Provision_PT_838_Security_Camera'
SAMSUNG_SNH_1011_N_WEBCAM = 'Samsung_SNH_1011_N_Webcam'
SIMPLEHOME_XCS7_1002_WHT_SECURITY_CAMERA = 'SimpleHome_XCS7_1002_WHT_Security_Camera'
SIMPLEHOME_XCS7_1003_WHT_SECURITY_CAMERA = 'SimpleHome_XCS7_1003_WHT_Security_Camera'

ALL_FOLDERS = [
    DANMINI_DOORBELL,
    ECOBEE_THERMOSTAT,
    # ENNIO_DOORBELL,
    PHILIPS_B120N10_BABY_MONITOR,
    PROVISION_PT_737E_SECURITY_CAMERA,
    PROVISION_PT_838_SECURITY_CAMERA,
    # SAMSUNG_SNH_1011_N_WEBCAM,
    SIMPLEHOME_XCS7_1002_WHT_SECURITY_CAMERA,
    SIMPLEHOME_XCS7_1003_WHT_SECURITY_CAMERA,   
]

# SUBFOLDERS
GAFGYT_ATTACKS = 'gafgyt_attacks'
MIRAI_ATTACKS = 'mirai_attacks'
ALL_SUBFOLDERS = [
    GAFGYT_ATTACKS,
    MIRAI_ATTACKS,
]

# TRAFFICS NAMES
GAFGYT_ATTACKS_COMBO = 'combo'
GAFGYT_ATTACKS_JUNK = 'junk'
GAFGYT_ATTACKS_SCAN = 'scan'
GAFGYT_ATTACKS_TCP = 'tcp'
GAFGYT_ATTACKS_UDP = 'udp'

ALL_GAFGYT_ATTACKS = [
    GAFGYT_ATTACKS_COMBO,
    GAFGYT_ATTACKS_JUNK,
    GAFGYT_ATTACKS_SCAN,
    GAFGYT_ATTACKS_TCP,
    GAFGYT_ATTACKS_UDP,
]

MIRAI_ATTACKS_ACK = 'ack'
MIRAI_ATTACKS_SCAN = 'scan'
MIRAI_ATTACKS_SYN = 'syn'
MIRAI_ATTACKS_UDP = 'udp'
MIRAI_ATTACKS_UDPPLAIN = 'udpplain'

ALL_MIRAI_ATTACKS = [
    MIRAI_ATTACKS_ACK,
    MIRAI_ATTACKS_SCAN,
    MIRAI_ATTACKS_SYN,
    MIRAI_ATTACKS_UDP,
    MIRAI_ATTACKS_UDPPLAIN,
]

BASE_DIRECTORY = '/media/nadir/data/venv/botnet/'
BENIGN_TRAFFIC = 'benign_traffic'


for i, folder in enumerate(ALL_FOLDERS):
    target = 10
#    target = 1
    dtarget = i
    if i == 0:
        all_devices_packets_info = pd.read_csv("{}{}/{}.csv".format(BASE_DIRECTORY, folder, BENIGN_TRAFFIC))
        #print('tempinfo', temp_info.shape)
        all_devices_packets_info['target'] = target
        all_devices_packets_info['dtarget'] = dtarget

    else:
        temp_info1 = pd.read_csv("{}{}/{}.csv".format(BASE_DIRECTORY, folder, BENIGN_TRAFFIC))
        #print('tempinfo', temp_info.shape)
        temp_info1['target'] = target
        temp_info1['dtarget'] = dtarget

        all_devices_packets_info = pd.concat([all_devices_packets_info, temp_info1])
        
    for subfolder in ALL_SUBFOLDERS:
        if subfolder == GAFGYT_ATTACKS:
            for i, ga_atack in enumerate(ALL_GAFGYT_ATTACKS):
                print(ga_atack)
                target = i
#                target = 0
                packetsInfo = pd.read_csv("{}{}/{}/{}.csv".format(BASE_DIRECTORY, folder, subfolder, ga_atack))
                packetsInfo['target'] = target
                packetsInfo['dtarget'] = dtarget
                all_devices_packets_info = pd.concat([all_devices_packets_info, packetsInfo])
                #print('packetsInfo', packetsInfo.shape)
                #print('tempinfo', temp_info.shape)

                
        elif subfolder == MIRAI_ATTACKS:
            for i, mi_atack in enumerate(ALL_MIRAI_ATTACKS):
                print(mi_atack)
#                target = 0
                target = i + 5
                packetsInfo = pd.read_csv("{}{}/{}/{}.csv".format(BASE_DIRECTORY, folder, subfolder, mi_atack))
                packetsInfo['target'] = target
                packetsInfo['dtarget'] = dtarget
                all_devices_packets_info = pd.concat([all_devices_packets_info, packetsInfo])
                #print('packetsInfo', packetsInfo.shape)
                #print('tempinfo', temp_info.shape)

print(all_devices_packets_info.shape)    

targets = all_devices_packets_info['target']
dtargets = all_devices_packets_info['dtarget']
all_devices_packets_info.drop('target', axis=1, inplace=True)
all_devices_packets_info.drop('dtarget', axis=1, inplace=True)
print(all_devices_packets_info.shape)


#min_max_scaler = preprocessing.MinMaxScaler()
#x = min_max_scaler.fit_transform(all_devices_packets_info)

standard_scaler = preprocessing.StandardScaler()
x = standard_scaler.fit_transform(all_devices_packets_info)

targets_array = targets.to_numpy()
dtargets_array = dtargets.to_numpy()

targets_category = np_utils.to_categorical(targets_array)
dtargets_category = np_utils.to_categorical(dtargets_array)

n_features = 1
x = x.reshape((x.shape[0], x.shape[1], n_features))



seed(123421412)
my_filters0 = 16
my_filters1 = 32
my_filters2 = 64
my_filters3 = 128
my_filters4 = 256
my_filters5 = 512
my_filters6 = 1024
my_kernel_size = 10
my_strides = 1

inputLayer = keras.layers.Input(shape=(115, 1))
#model.add(Conv1D(my_filters, my_kernel_size, input_shape = x_train.shape[1:3], padding='same', strides = my_strides, activation = 'relu', kernel_initializer='glorot_uniform'))
 



conv1 = keras.layers.Conv1D(my_filters0, my_kernel_size, activation='relu', padding='same', kernel_initializer='glorot_uniform')(inputLayer)
pool1 = keras.layers.MaxPool1D(pool_size=2)(conv1)
conv2 = keras.layers.Conv1D(my_filters1, my_kernel_size, activation='relu', padding='same', kernel_initializer='glorot_uniform')(pool1)
pool2 = keras.layers.MaxPool1D(pool_size=2)(conv2)
conv3 = keras.layers.Conv1D(my_filters2, my_kernel_size, activation='relu', padding='same', kernel_initializer='glorot_uniform')(pool2)
pool3 = keras.layers.MaxPool1D(pool_size=2)(conv3)
conv4 = keras.layers.Conv1D(my_filters3, my_kernel_size, activation='relu', padding='same', kernel_initializer='glorot_uniform')(pool3)
pool4 = keras.layers.MaxPool1D(pool_size=2)(conv4)
conv5 = keras.layers.Conv1D(my_filters4, my_kernel_size, activation='relu', padding='same', kernel_initializer='glorot_uniform')(pool4)
pool5 = keras.layers.MaxPool1D(pool_size=2)(conv5)
conv6 = keras.layers.Conv1D(my_filters5, my_kernel_size, activation='relu', padding='same', kernel_initializer='glorot_uniform')(pool5)
pool6 = keras.layers.MaxPool1D(pool_size=2)(conv6)
#conv7 = keras.layers.Conv1D(1024, 5, activation='relu', padding='same', data_format='channels_first')(pool6)
#pool7 = keras.layers.MaxPool1D(pool_size=2)(conv7)

#conv3 = keras.layers.Conv1D(150, 3, activation='relu', padding='same', strides=2)(conv2)
#conv4 = keras.layers.Conv1D(100, 3, activation='relu', padding='same', strides=2)(conv3)
#conv5 = keras.layers.Conv1D(50, 3, activation='relu', padding='same', strides=2)(conv4)
#conv6 = keras.layers.Conv1D(30, 3, activation='relu', padding='same', strides=2)(conv5)

# convert to vector
flat = keras.layers.Flatten()(pool6)
#dense1 = keras.layers.Dense(1024, activation='relu')(flat)
#dense2 = keras.layers.Dense(512, activation='relu')(flat)
#dense3 = keras.layers.Dense(256, activation='relu')(dense2)
outLayer = keras.layers.Dense(11, activation='softmax', kernel_initializer='lecun_uniform')(flat)





convModel = Model(inputLayer, outLayer)

convModel.summary()


adam = keras.optimizers.Adam(lr=1e-5)
#convModel.compile(optimizer=keras.optimizers.SGD(lr=0.01, momentum=0.9, decay=0.01), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
#convModel.compile(optimizer=keras.optimizers.Adam(lr= 1e-4, decay=1), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
convModel.compile(optimizer=adam, loss="categorical_crossentropy",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
#convModel.load_weights(‘model.h5’, by_name=True)

convModel.load_weights('weights00000070.h5', by_name=True)

mc = keras.callbacks.ModelCheckpoint('weights{epoch:08d}.h5', save_weights_only=True, period=10)

networkHistory = convModel.fit(x, targets_category, batch_size=512 , epochs=100, validation_split=0.2, shuffle=True, callbacks=[mc])



