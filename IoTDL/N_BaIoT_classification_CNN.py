#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May  3 19:13:38 2020

@author: nadir
"""
from __future__ import print_function
import pandas as pd
import numpy as np
from sklearn import preprocessing
import matplotlib.pyplot as plt
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from keras.callbacks import TensorBoard

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
#    ECOBEE_THERMOSTAT,
#    # ENNIO_DOORBELL,
#    PHILIPS_B120N10_BABY_MONITOR,
#    PROVISION_PT_737E_SECURITY_CAMERA,
#    PROVISION_PT_838_SECURITY_CAMERA,
#    # SAMSUNG_SNH_1011_N_WEBCAM,
#    SIMPLEHOME_XCS7_1002_WHT_SECURITY_CAMERA,
#    SIMPLEHOME_XCS7_1003_WHT_SECURITY_CAMERA,   
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




#all_devices_packets_info_array = all_devices_packets_info.to_numpy(dtype='float32')
#targets_array = targets.to_numpy()
#dtargets_array = dtargets.to_numpy()



#knn = KNeighborsClassifier(n_neighbors=6, metric='minkowski', p=2)
#x_train, x_test, y_train, y_test = train_test_split(all_devices_packets_info_array, targets_array, test_size=0.3, random_state=42, stratify=targets_array)

from keras.models import Model
from keras import layers
import keras
from keras.utils import np_utils

#min_max_scaler = preprocessing.MinMaxScaler()
#x = min_max_scaler.fit_transform(all_devices_packets_info)

standard_scaler = preprocessing.StandardScaler()
x = standard_scaler.fit_transform(all_devices_packets_info)


	
#from sklearn.decomposition import PCA as sklearnPCA
#sklearn_pca = sklearnPCA(n_components=30)
#Y_sklearn = sklearn_pca.fit_transform(x)

print(x.shape)
#print(Y_sklearn.shape)


targets_array = targets.to_numpy()
dtargets_array = dtargets.to_numpy()

targets_category = np_utils.to_categorical(targets_array)
dtargets_category = np_utils.to_categorical(dtargets_array)



from keras.preprocessing import sequence
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
from keras.layers import Embedding
from keras.layers import Conv1D, GlobalMaxPooling1D
from keras.datasets import imdb


## set parameters:
#max_features = 5000
#maxlen = 400
#batch_size = 32
#embedding_dims = 50
#filters = 250
#kernel_size = 3
#hidden_dims = 250
#epochs = 2

#model = Sequential()
#
## we start off with an efficient embedding layer which maps
## our vocab indices into embedding_dims dimensions
#model.add(Embedding(6331884, 115, input_length=115))
#model.add(Dropout(0.2))
#
## we add a Convolution1D, which will learn filters
## word group filters of size filter_length:
#model.add(Conv1D(100, kernel_size, padding='valid', activation='relu', strides=1))
## we use max pooling:
#model.add(GlobalMaxPooling1D())
#
## We add a vanilla hidden layer:
#model.add(Dense(hidden_dims))
#model.add(Dropout(0.2))
#model.add(Activation('relu'))
#
## We project onto a single unit output layer, and squash it with a sigmoid:
#model.add(Dense(11))
#model.add(Activation('softmax'))
#
#model.compile(loss='binary_crossentropy',
#              optimizer='adam',
#              metrics=['accuracy'])
#model.fit(x, targets_array, batch_size=batch_size, epochs=epochs, validation_split=0.2)


##indicate folder to save, plus other options
#tensorboard = TensorBoard(log_dir='./logs/run1', histogram_freq=1,
#    write_graph=True, write_images=False)  
#
##save it in your callback list
#callbacks_list = [tensorboard]


n_features = 1
x = x.reshape((x.shape[0], x.shape[1], n_features))

#Y_sklearn = Y_sklearn.reshape((Y_sklearn.shape[0], Y_sklearn.shape[1], n_features))



inputLayer = layers.Input(shape=(115, 1))
# =============================================================================
# conv1 = layers.Conv2D(16, 3, activation='relu', padding='same')(inputLayer)
# pool1 = layers.MaxPool2D(pool_size=2)(conv1)
# 
# conv2 = layers.Conv2D(32, 3, activation='relu', padding='same')(pool1)
# pool2 = layers.MaxPool2D(pool_size=2)(conv2)
# =============================================================================

# strides=2 i used instead pool layers
conv1 = layers.Conv1D(16, 5, activation='relu', padding='same')(inputLayer)
pool1 = layers.MaxPool1D(pool_size=2)(conv1)
conv2 = layers.Conv1D(32, 5, activation='relu', padding='same')(pool1)
pool2 = layers.MaxPool1D(pool_size=2)(conv2)
conv3 = layers.Conv1D(64, 5, activation='relu', padding='same')(pool2)
pool3 = layers.MaxPool1D(pool_size=2)(conv3)
conv4 = layers.Conv1D(128, 5, activation='relu', padding='same')(pool3)
pool4 = layers.MaxPool1D(pool_size=2)(conv4)
conv5 = layers.Conv1D(256, 5, activation='relu', padding='same')(pool4)
pool5 = layers.MaxPool1D(pool_size=2)(conv5)
conv6 = layers.Conv1D(512, 5, activation='relu', padding='same')(pool5)
pool6 = layers.MaxPool1D(pool_size=2)(conv6)
#conv7 = layers.Conv1D(1024, 5, activation='relu', padding='same', data_format='channels_first')(pool6)
#pool7 = layers.MaxPool1D(pool_size=2)(conv7)

#conv3 = layers.Conv1D(150, 3, activation='relu', padding='same', strides=2)(conv2)
#conv4 = layers.Conv1D(100, 3, activation='relu', padding='same', strides=2)(conv3)
#conv5 = layers.Conv1D(50, 3, activation='relu', padding='same', strides=2)(conv4)
#conv6 = layers.Conv1D(30, 3, activation='relu', padding='same', strides=2)(conv5)

# convert to vector
flat = layers.Flatten()(pool6)
#dense1 = layers.Dense(1024, activation='relu')(flat)
#dense2 = layers.Dense(512, activation='relu')(flat)
#dense3 = layers.Dense(256, activation='relu')(dense2)
outLayer = layers.Dense(11, activation='softmax')(flat)


convModel = Model(inputLayer, outLayer)

convModel.summary()
import tensorflow as tf
import keras



#convModel.compile(optimizer=keras.optimizers.SGD(lr=0.01, momentum=0.9, decay=0.01), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
#convModel.compile(optimizer=keras.optimizers.Adam(lr= 1e-4, decay=1), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
convModel.compile(optimizer=tf.train.MomentumOptimizer(1e-5, momentum=0.9), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
#convModel.load_weights(‘model.h5’, by_name=True)

mc = keras.callbacks.ModelCheckpoint('weights{epoch:08d}.h5', save_weights_only=True, period=10)

networkHistory = convModel.fit(x, targets_category, batch_size=512 , epochs=100, validation_split=0.2, shuffle=True, callbacks=[mc])

#for i in range(50):
#    if i != 0:
#        convModel.load_weights(BASE_DIRECTORY + 'models/model{}.h5'.format(i-1), by_name=True)
#    networkHistory = convModel.fit(x, targets_category, batch_size=512 , epochs=10, validation_split=0.2, shuffle=True)
#    convModel.save(BASE_DIRECTORY + 'models/model{}.h5'.format(i))



