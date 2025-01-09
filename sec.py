import pyshark
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import matplotlib.pyplot as plt
import psutil
import time

# 设置TShark路径
pyshark.tshark.tshark.get_process_path = lambda tshark_path=None: tshark_path or r"C:\MZGH\VPN\Wireshark\tshark.exe"

# 设置PCAP文件路径
pcap_file = r"C:\Users\zyy\Documents\persinal\work\buhuo.pcap"

def process_pcap():
    # 记录开始时间
    start_time = time.time()

    # 监控负载：CPU和内存使用率
    cpu_start = psutil.cpu_percent(interval=1)
    memory_start = psutil.virtual_memory().percent

    # 读取PCAP文件
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)

    data = []
    for packet in cap:  # 使用同步方式逐个包读取
        try:
            if hasattr(packet, 'ip'):
                packet_data = {
                    'packet_size': len(packet),
                    'source_ip': packet.ip.src,
                    'destination_ip': packet.ip.dst,
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A',
                    'timestamp': packet.sniff_time.timestamp(),  # 获取时间戳
                }
                data.append(packet_data)
        except AttributeError as e:
            continue

    # 关闭文件捕获
    cap.close()

    # 将提取的数据转换为DataFrame
    df = pd.DataFrame(data)

    # 打印前几行数据
    print(df.head())

    # 数据包大小分布图
    df['packet_size'].plot(kind='hist', bins=50, title='Packet Size Distribution')
    plt.xlabel('Packet Size')
    plt.ylabel('Frequency')
    plt.show()

    # 假设标签（0 - 正常流量，1 - DDoS攻击流量）
    df['label'] = 0  # 默认标签为正常流量
    df.loc[df['packet_size'] > 500, 'label'] = 1  # 假设大于500字节为攻击流量

    # 特征与标签
    X = df[['packet_size', 'timestamp']]
    y = df['label']

    # 数据集拆分
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # 训练模型
    clf_start_time = time.time()  # 训练开始时间
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    clf_end_time = time.time()  # 训练结束时间

    # 预测
    y_pred = clf.predict(X_test)

    # 计算准确率
    accuracy = accuracy_score(y_test, y_pred)
    print(f'Accuracy: {accuracy:.4f}')
    print(classification_report(y_test, y_pred))

    # 记录训练时长和其他阶段的时长
    training_time = clf_end_time - clf_start_time
    total_time = time.time() - start_time
    print(f"Model training time: {training_time:.2f} seconds")
    print(f"Total processing time: {total_time:.2f} seconds")

    # 监控负载：CPU和内存使用率
    cpu_end = psutil.cpu_percent(interval=1)
    memory_end = psutil.virtual_memory().percent
    print(f"CPU usage before processing: {cpu_start}%")
    print(f"CPU usage after processing: {cpu_end}%")
    print(f"Memory usage before processing: {memory_start}%")
    print(f"Memory usage after processing: {memory_end}%")

    # 可视化：DDoS攻击检测结果（包大小 vs 时间戳）
    plt.scatter(df['timestamp'], df['packet_size'], c=df['label'], cmap='coolwarm', marker='o')
    plt.title('DDoS Attack Detection: Packet Size vs Timestamp')
    plt.xlabel('Timestamp')
    plt.ylabel('Packet Size')
    plt.show()

if __name__ == "__main__":
    process_pcap()
