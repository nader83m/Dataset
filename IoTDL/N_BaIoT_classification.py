#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun May  3 19:13:38 2020

@author: nadir
"""
import pandas as pd
import numpy as np
from sklearn import preprocessing
import matplotlib.pyplot as plt
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split


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

BASE_DIRECTORY = '/media/nadir/data/venv/IoT/IoT_botnet/'
BENIGN_TRAFFIC = 'benign_traffic'


for i, folder in enumerate(ALL_FOLDERS):
#    target = 10
    target = 10
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
                packetsInfo = pd.read_csv("{}{}/{}/{}.csv".format(BASE_DIRECTORY, folder, subfolder, ga_atack))
                packetsInfo['target'] = target
                packetsInfo['dtarget'] = dtarget
                all_devices_packets_info = pd.concat([all_devices_packets_info, packetsInfo])
                #print('packetsInfo', packetsInfo.shape)
                #print('tempinfo', temp_info.shape)

                
        elif subfolder == MIRAI_ATTACKS:
            for i, mi_atack in enumerate(ALL_MIRAI_ATTACKS):
                print(mi_atack)
                target = i + 5
#                target = i + 5
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


all_devices_packets_info_array = all_devices_packets_info.to_numpy(dtype='float32')
targets_array = targets.to_numpy()
dtargets_array = dtargets.to_numpy()



#knn = KNeighborsClassifier(n_neighbors=6, metric='minkowski', p=2)
#x_train, x_test, y_train, y_test = train_test_split(all_devices_packets_info_array, targets_array, test_size=0.3, random_state=42, stratify=targets_array)

from keras.models import Model, Sequential
from keras.layers import Input, Dense, Dropout
from keras.utils import np_utils

min_max_scaler = preprocessing.MinMaxScaler()
x = min_max_scaler.fit_transform(all_devices_packets_info_array)



targets_category = np_utils.to_categorical(targets_array)
dtargets_category = np_utils.to_categorical(dtargets_array)

a = Input(shape=(115,))
b = Dense(100, activation='relu')(a)
bb = Dropout(0.1)(b)
c = Dense(85, activation='relu')(bb)
cc = Dropout(0.1)(c)
d = Dense(70, activation='relu')(cc)
dd = Dropout(0.1)(d)
e = Dense(55, activation='relu')(dd)
ee = Dropout(0.1)(e)
f = Dense(40, activation='relu')(ee)
ff = Dropout(0.1)(f)
g = Dense(35, activation='relu')(ff)
gg = Dropout(0.1)(g)
h = Dense(20, activation='relu')(g)
hh = Dropout(0.1)(h)

##i = Dense(35, activation='relu')(h)
##j = Dense(25, activation='relu')(i)
#
b1 = Dense(11, activation='softmax', name='active1')(hh)
#
model = Model(inputs=a, outputs=b1)
print(model.summary())
from keras.optimizers import adam as Adam
from keras.optimizers import sgd as SGD

model.compile(optimizer=Adam(lr= 1e-3), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
nh = model.fit(x, targets_category, batch_size=1024 , epochs=500, validation_split=0.2, shuffle=True)


#a = Input(shape=(115,))
#b = Dense(105, activation='relu')(a)
#c = Dense(90, activation='relu')(b)
#d = Dense(75, activation='relu')(c)
#e = Dense(50, activation='relu')(d)
#f = Dense(35, activation='relu')(e)
#g1 = Dense(20, activation='relu')(f)
#g2 = Dense(20, activation='relu')(f)
#h = Dense(13, activation='relu')(g2)
#b1 = Dense(11, activation='softmax', name='active1')(g1)
#b2 = Dense(7, activation='softmax', name='active2')(h)




#b2= Dense(7,activation='softmax')(b)

#model = Sequential()
#model.add(Dense(100, activation='relu', input_dim=115))
#model.add(Dense(70, activation='relu'))
#model.add(Dense(50, activation='relu'))
#model.add(Dense(30, activation='relu'))
#model.add(Dense(11, activation='softmax'))
#model.compile(optimizer='adam', loss='mse',  metrics=['accuracy'])
#model.fit(x, targets_category, epochs=100, batch_size=32, validation_split=0.2)

#

#model = Model(inputs=a, outputs=[b1,b2])
#print(model.summary())
#from keras.optimizers import adam as Adam
#model.compile(optimizer=Adam(lr= 1e-3), loss="mean_squared_error",  metrics=['accuracy']) #loss=  {'active1':  tp_mse_loss ,'activation_95':  tp_loss , 'activation_96': tp_loss  }
#model.fit(x, [targets_category,dtargets_category], batch_size=512 , epochs=500, validation_split=0.2 )


#knn = KNeighborsClassifier(n_neighbors=7)                        
#knn.fit(x_train, y_train)
#y_predict = knn.predict(x_test)
#print(knn.score(x_test, y_test))
#print(y_predict)

            
