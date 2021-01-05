# Gerardo Armenta
# Nov 30, 2020
# Assignment 5 Netflow Packet Analysis

import pandas as pd
import matplotlib.pyplot as plt


# Calculates the average packets size from the csv file
def avgPacketSize():
    file = pd.read_csv('Netflow_dataset.csv')
    # gets the mean from the division of doctets and dpkts
    fileAvg = (file['doctets'] / file['dpkts']).mean()
    print('The average packet size is: ', fileAvg, '\n')


def flowSizesCCDFLinear():
    file = pd.read_csv('Netflow_dataset.csv')
    file['CCDF'] = file['last'] - file['first']
    rowNum = len(file.index)
    print('\n', file)
    x = []
    y = []
    # fill the x and y values for the graph
    for i in range(rowNum):
        x.append(i)
    for f in file['CCDF']:
        y.append(f)
    fig, ax = plt.subplots()
    plt.title('Linear CCDF Graph')
    plt.xlabel('Index')
    plt.ylabel('CCDF')
    ax.plot(x, y, label='linear')
    plt.show()


def flowSizesCCDFLog():
    file = pd.read_csv('Netflow_dataset.csv')
    file['CCDF'] = file['last'] - file['first']
    rowNum = len(file.index)
    print('\n', file)
    x = []
    y = []
    # fill the x and y values for the graph
    for i in range(rowNum):
        x.append(i)
    for f in file['CCDF']:
        y.append(f)
    plt.rcParams['agg.path.chunksize'] = 10000
    fig, ax = plt.subplots()
    plt.title('Logarithmic CCDF Graph')
    plt.xlabel('Index')
    plt.ylabel('CCDF')
    ax.loglog(x, y, label='log')
    plt.show()


def flowSizesLinear():
    file = pd.read_csv('Netflow_dataset.csv')
    file['flow_sizes'] = file['doctets'] / file['dpkts']
    print(file)
    rowNum = len(file.index)
    x = []
    y = []
    # fill the x and y values for the graph
    for i in range(rowNum):
        x.append(i)
    for f in file['flow_sizes']:
        y.append(f)
    fig, ax = plt.subplots()
    ax.plot(x, y, label='linear')
    plt.title('Linear Flow Size Graph')
    plt.xlabel('Index')
    plt.ylabel('Flow Size')
    plt.show()


def flowSizesLog():
    file = pd.read_csv('Netflow_dataset.csv')
    file['flow_sizes'] = file['doctets'] / file['dpkts']
    print(file)
    rowNum = len(file.index)
    x = []
    y = []
    # fill the x and y values for the graph
    for i in range(rowNum):
        x.append(i)
    for f in file['flow_sizes']:
        y.append(f)
    fig, ax = plt.subplots()
    ax.loglog(x, y, label='log')
    plt.title('Flow Sizes Logarithmic Graph')
    plt.xlabel('Index')
    plt.ylabel('Flow Size')
    plt.show()


def routerTraffic():
    file = pd.read_csv('Netflow_dataset.csv')
    # This is for the srcport
    df = pd.DataFrame()
    df['SrcPort'] = file['srcport']
    df['Data'] = file['doctets']
    # Sums the data that have the same SrcPort number
    df['Data'] = df.groupby(['SrcPort'])['Data'].transform('sum')
    # Deletes the duplicate SrcPort numbers
    newDf = df.drop_duplicates(subset=['SrcPort'])
    # Here we compute the percentage based on the top 10 ports only
    newDf['Percentage'] = (100 * newDf['Data']) / newDf.sort_values(by='Data', ascending=False)['Data'].head(10).sum()
    # Lists the top ten port numbers in descending order with its corresponding traffic percentage
    source = newDf.sort_values(by='Data', ascending=False).head(10)
    print(source[['SrcPort', 'Percentage']])

    # This is for the dstport
    dest = pd.DataFrame()
    dest['DstPort'] = file['dstport']
    dest['Data'] = file['doctets']
    # Sums the data that have the same DstPort number
    dest['Data'] = dest.groupby(['DstPort'])['Data'].transform('sum')
    # Deletes the duplicate DstPort numbers
    nDf = dest.drop_duplicates(subset=['DstPort'])
    # Here we compute the percentage based on the top 10 ports only
    nDf['Percentage'] = (100 * nDf['Data']) / nDf.sort_values(by='Data', ascending=False)['Data'].head(10).sum()
    # Lists the top ten port numbers in descending order with its corresponding traffic percentage
    destination = nDf.sort_values(by='Data', ascending=False).head(10)
    print(destination[['DstPort', 'Percentage']])


def trafficVols():
    file = pd.read_csv('Netflow_dataset.csv')
    df = pd.DataFrame()
    df['SrcAddr'] = file['srcaddr']
    df['Mask'] = file['src_mask']
    df['Data'] = file['doctets']
    df['Data'] = df.groupby(['SrcAddr'])['Data'].transform('sum')
    df = df.drop_duplicates(subset=['SrcAddr'])
    # Gets the percentage of the top 0.1%
    zeroOne = df.sort_values(by='Data', ascending=False).head(int(len(df)*(0.1/100)))
    print('Top 0.1%:  ', zeroOne['Data'].sum() * 100 / file['doctets'].sum())

    # Gets the percentage of the top 1%
    one = df.sort_values(by='Data', ascending=False).head(int(len(df)*(1/100)))
    print('Top 1%:    ', one['Data'].sum() * 100 / file['doctets'].sum())

    # Gets the percentage of the top 10%
    ten = df.sort_values(by='Data', ascending=False).head(int(len(df) * (10 / 100)))
    print('Top 10%:   ', ten['Data'].sum() * 100 / file['doctets'].sum())

    # Traffic on source mask 0
    mask = pd.DataFrame()
    mask['SrcAddr'] = file['srcaddr']
    mask['Mask'] = file['src_mask']
    mask['Data'] = file['doctets']
    mask = mask.query('Mask == 0')
    print('Percentage where source mask is 0:   ', mask['Data'].sum() * 100 / file['doctets'].sum())

    # Removes rows were Mask is 0
    df = df.query('Mask != 0')
    # Gets the percentage of the top 0.1% without mask 0
    maskZeroOne = df.sort_values(by='Data', ascending=False).head(int(len(df) * (0.1 / 100)))
    print('Top 0.1% without mask 0:  ', maskZeroOne['Data'].sum() * 100 / file['doctets'].sum())

    # Gets the percentage of the top 1%
    maskOne = df.sort_values(by='Data', ascending=False).head(int(len(df) * (1 / 100)))
    print('Top 1% without mask 0:    ', maskOne['Data'].sum() * 100 / file['doctets'].sum())

    # Gets the percentage of the top 10%
    maskTen = df.sort_values(by='Data', ascending=False).head(int(len(df) * (10 / 100)))
    print('Top 10% without mask 0:   ', maskTen['Data'].sum() * 100 / file['doctets'].sum())


def eAns():
    file = pd.read_csv('Netflow_dataset.csv')
    df = pd.DataFrame()
    df['srcaddr'] = file['srcaddr']
    df['dstaddr'] = file['dstaddr']
    df['dpkts'] = file['dpkts']
    df['doctets'] = file['doctets']

    # This is the traffic sent by A
    srcIp = df.groupby(by='srcaddr').sum().filter(like='128.112.', axis=0)
    srcIp = srcIp.drop(['131.128.112.0', '188.128.112.0', '213.128.112.0', '64.128.112.0', '95.128.112.0'])
    aTraffic = srcIp['doctets'].sum() * 100 / file['doctets'].sum()
    aPackets = srcIp['dpkts'].sum() * 100 / file['dpkts'].sum()

    # This is the traffic sent to A
    dstIp = df.groupby(by='dstaddr').sum().filter(like='128.112.', axis=0)
    dstIp = dstIp.drop(['113.128.112.0', '131.128.112.0', '128.128.112.0', '202.128.112.0', '209.128.112.0',
                        '72.128.112.0', '83.128.112.0'])
    a2Traffic = dstIp['doctets'].sum() * 100 / file['doctets'].sum()
    a2Packets = dstIp['dpkts'].sum() * 100 / file['dpkts'].sum()

    # Shows the percentage of the traffic by and to A
    print('\nTotal data traffic percentage sent by A is:    ', aTraffic)
    print('\nTotal packet traffic percentage sent by A is:  ', aPackets)
    print('\nTotal data traffic percentage sent to A is:    ', a2Traffic)
    print('\nTotal packet traffic percentage sent to A is:  ', a2Packets)


avgPacketSize()
flowSizesCCDFLog()
flowSizesCCDFLinear()
flowSizesLinear()
flowSizesLog()
routerTraffic()
trafficVols()
eAns()
