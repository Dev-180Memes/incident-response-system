import pickle
import pandas as pd


class IncidentDetection:
    def __init__(self, feature_dict):
        with open('constants.pkl', 'rb') as file:
            self.logReg = pickle.load(file)
        # Load df of to predict
        self.df = pd.DataFrame(feature_dict, index=[0])

    @staticmethod
    def calculateIntensityFrequencyImpact(df):
        df['Intensity'] = (df[' Total Fwd Packets'] + df[' Total Backward Packets'] +
                           df[' Fwd Packet Length Mean'] + df[' Bwd Packet Length Mean'] +
                           df['Fwd PSH Flags'] + df[' SYN Flag Count'] + df[' RST Flag Count'] +
                           df[' PSH Flag Count'] + df[' ACK Flag Count'] + df[' URG Flag Count'] +
                           df[' CWE Flag Count'] + df[' ECE Flag Count'])
        df['Frequency'] = df[' Flow Packets/s'] + df['Flow Bytes/s']
        df['Impact_Extent'] = (df[' Destination Port'] + df[' Flow Duration'] +
                               df[' Bwd Avg Bytes/Bulk'] + df['Fwd Avg Bytes/Bulk'])
        return df

    def calculateSeverity(self, alpha, beta, gamma):
        df = self.calculateIntensityFrequencyImpact(self.df)
        df['Severity'] = alpha * df['Intensity'] + beta * df['Frequency'] + gamma * df['Impact_Extent']
        return df

    def getSeverityScore(self):
        alpha, beta, gamma = self.logReg.coef_
        df = self.calculateSeverity(alpha, beta, gamma)
        severity_score = df['Severity'].values[0]
        return severity_score

    def rankSeverity(self):
        severity_score = self.getSeverityScore()
        low_severity_threshold = -2.3433906255080847
        mid_severity_threshold = 5.476629648753329

        if severity_score < low_severity_threshold:
            return 1
        elif low_severity_threshold <= severity_score < mid_severity_threshold:
            return 2
        else:
            return 3


data = {' Destination Port': 21,
        ' Flow Duration': 307,
        ' Total Fwd Packets': 2,
        ' Total Backward Packets': 1,
        'Total Length of Fwd Packets': 14,
        ' Total Length of Bwd Packets': 0,
        ' Fwd Packet Length Max': 14,
        ' Fwd Packet Length Min': 0,
        ' Fwd Packet Length Mean': 7.0,
        ' Fwd Packet Length Std': 9.899494937,
        'Bwd Packet Length Max': 0,
        ' Bwd Packet Length Min': 0,
        ' Bwd Packet Length Mean': 0.0,
        ' Bwd Packet Length Std': 0.0,
        'Flow Bytes/s': 45602.60586,
        ' Flow Packets/s': 9771.986971,
        ' Flow IAT Mean': 153.5,
        ' Flow IAT Std': 72.83199846,
        ' Flow IAT Max': 205,
        ' Flow IAT Min': 102,
        'Fwd IAT Total': 307,
        ' Fwd IAT Mean': 307.0,
        ' Fwd IAT Std': 0.0,
        ' Fwd IAT Max': 307,
        ' Fwd IAT Min': 307,
        'Bwd IAT Total': 0,
        ' Bwd IAT Mean': 0.0,
        ' Bwd IAT Std': 0.0,
        ' Bwd IAT Max': 0,
        ' Bwd IAT Min': 0,
        'Fwd PSH Flags': 1,
        ' Bwd PSH Flags': 0,
        ' Fwd URG Flags': 0,
        ' Bwd URG Flags': 0,
        ' Fwd Header Length': 64,
        ' Bwd Header Length': 20,
        'Fwd Packets/s': 6514.65798,
        ' Bwd Packets/s': 3257.32899,
        ' Min Packet Length': 0,
        ' Max Packet Length': 14,
        ' Packet Length Mean': 7.0,
        ' Packet Length Std': 8.082903769,
        ' Packet Length Variance': 65.33333333,
        'FIN Flag Count': 0,
        ' SYN Flag Count': 1,
        ' RST Flag Count': 0,
        ' PSH Flag Count': 0,
        ' ACK Flag Count': 1,
        ' URG Flag Count': 0,
        ' CWE Flag Count': 0,
        ' ECE Flag Count': 0,
        ' Down/Up Ratio': 0,
        ' Average Packet Size': 9.333333333,
        ' Avg Fwd Segment Size': 7.0,
        ' Avg Bwd Segment Size': 0.0,
        ' Fwd Header Length.1': 64,
        'Fwd Avg Bytes/Bulk': 0,
        ' Fwd Avg Packets/Bulk': 0,
        ' Fwd Avg Bulk Rate': 0,
        ' Bwd Avg Bytes/Bulk': 0,
        ' Bwd Avg Packets/Bulk': 0,
        'Bwd Avg Bulk Rate': 0,
        'Subflow Fwd Packets': 2,
        ' Subflow Fwd Bytes': 14,
        ' Subflow Bwd Packets': 1,
        ' Subflow Bwd Bytes': 0,
        'Init_Win_bytes_forward': 229,
        ' Init_Win_bytes_backward': 0,
        ' act_data_pkt_fwd': 0,
        ' min_seg_size_forward': 32,
        'Active Mean': 0.0,
        ' Active Std': 0.0,
        ' Active Max': 0,
        ' Active Min': 0,
        'Idle Mean': 0.0,
        ' Idle Std': 0.0,
        ' Idle Max': 0,
        ' Idle Min': 0,
        ' Label': 'FTP-Patator'}

incident = IncidentDetection(data)
print(incident.rankSeverity())

if __name__ == '__main__':
    pass
