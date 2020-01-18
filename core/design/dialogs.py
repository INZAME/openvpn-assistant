#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtWidgets

def connect(window):
    answer = QtWidgets.QMessageBox.question(
                window, 'Continue?', "Do u want to connect?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No)
    return answer

def no_openvpn(window):
    answer = QtWidgets.QMessageBox.question(
                        window, 'No OVPN installed',
                        'Start installation manager?',
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                        QtWidgets.QMessageBox.Yes)
    return answer

def open_file(window):
    this = QtWidgets.QFileDialog.getOpenFileName(
            window, 'Open file', '.', options=QtWidgets.QFileDialog.Options())[0]
    return this

def close_me(window):
    answer = QtWidgets.QMessageBox.question(
            window, 'Message', "Are you sure to quit?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No)
    return answer