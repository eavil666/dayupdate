# -*- coding: utf-8 -*-
"""main.py 业务纯逻辑测试（不触网、不读写真实业务文件）"""
import ipaddress

import main


def test_is_private_ip():
    assert main.is_private_ip('192.168.1.1') is True
    assert main.is_private_ip('10.0.0.1') is True
    assert main.is_private_ip('8.8.8.8') is False


def test_is_valid_public_ip():
    assert main.is_valid_public_ip('8.8.8.8') is True
    assert main.is_valid_public_ip('192.168.1.1') is False   # 私网
    assert main.is_valid_public_ip('999.1.1.1') is False     # 非法


def test_local_ip_label():
    assert main.local_ip_label('abc') == '无效IP'
    assert main.local_ip_label('192.168.1.1') == '内网/保留地址'
    assert main.local_ip_label('8.8.8.8') is None


def test_parse_region():
    # ip2region 格式：国家|省份|城市|ISP|编码
    loc, prov, city = main.parse_region('中国|广东省|广州市|电信|0')
    assert loc == '广东省 广州市 电信'
    assert prov == '广东省' and city == '广州市'
    # 字段不全时回退
    loc2, prov2, city2 = main.parse_region('中国|0')
    assert loc2 == '中国|0' and prov2 == '中国' and city2 == '中国'
    assert main.parse_region(None) == ('未知', '未知', '未知')


def test_format_online_result():
    assert main.format_online_result({'status': 'success',
                                      'country': '中国', 'regionName': '广东',
                                      'city': '广州', 'isp': '电信'}) == '中国 广东 广州 电信'
    assert main.format_online_result({'status': 'fail', 'message': 'private range'}) == 'private range'
    assert main.format_online_result({'status': 'fail'}) == '查询失败'


def _conf():
    return {
        'nets': [ipaddress.ip_network('10.0.0.0/8')],
        'zones': {'内网'},
        'geos': {'北京'},
    }


def test_classify():
    c = _conf()
    assert main.classify('10.1.1.1', '', '', c) == '内网'
    assert main.classify('172.16.0.5', '内网', '北京', c) == '内网'
    assert main.classify('8.8.8.8', '', '', c) == '外网'
    assert main.classify('172.16.0.5', '', '', c) == '待确认'
    assert main.classify('bad-ip', '', '', c) == '未知'


def test_parse_ip_range():
    r = main._parse_ip_range('10.0.0.1-10.0.0.10')
    assert len(r) == 10
    assert r[0] == '10.0.0.1' and r[-1] == '10.0.0.10'
    # 简写范围
    r2 = main._parse_ip_range('172.16.70.226-230')
    assert len(r2) == 5 and r2[0] == '172.16.70.226' and r2[-1] == '172.16.70.230'
    # 单 IP
    assert main._parse_ip_range('8.8.8.8') == ['8.8.8.8']
    # 不支持 CIDR / 空串 → 空列表
    assert main._parse_ip_range('192.168.1.0/24') == []
    assert main._parse_ip_range('') == []


def test_is_excluded_ip(monkeypatch):
    monkeypatch.setattr(main, 'EXCLUDED_IP_NETWORKS',
                        [ipaddress.ip_network('10.0.0.0/8'),
                         ipaddress.ip_address('192.168.9.9')])
    assert main.is_excluded_ip('10.1.2.3') is True
    assert main.is_excluded_ip('192.168.9.9') is True
    assert main.is_excluded_ip('8.8.8.8') is False
    assert main.is_excluded_ip('bad') is False
