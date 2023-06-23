import sys
from PySide6 import QtWidgets
from PySide6.QtWidgets import QMessageBox

from AES.aescipher import AESCipher


class MyWidget(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle("AES 加解密")
        self.setFixedSize(400, 300)
        self.setup_ui()
        self.echo()

    def setup_ui(self) -> None:
        key_label = QtWidgets.QLabel("Key:")
        self.iv_label = QtWidgets.QLabel("IV:")
        data_label = QtWidgets.QLabel("Data:")
        output_label = QtWidgets.QLabel("Output:")
        mode_label = QtWidgets.QLabel("Mode:")

        self.key_plain_text_edit = QtWidgets.QPlainTextEdit()
        self.iv_plain_text_edit = QtWidgets.QPlainTextEdit()
        self.data_plain_text_edit = QtWidgets.QPlainTextEdit()
        self.output_text_browser = QtWidgets.QTextBrowser()
        self.mode_combo_box = QtWidgets.QComboBox()

        self.mode_combo_box.addItems(["ECB", "CBC", "CFB", "OFB", "CTR"])
        self.encrypt_button = QtWidgets.QPushButton("Encrypt")
        self.decrypt_button = QtWidgets.QPushButton("Decrypt")

        # 设置默认值和提示文本
        self.key_plain_text_edit.setPlainText("Thats my Kung Fu")
        self.iv_plain_text_edit.setPlainText("1234567812345678")
        self.data_plain_text_edit.setPlaceholderText("Enter data here")

        data_layout = QtWidgets.QVBoxLayout()
        data_layout.addWidget(self.data_plain_text_edit)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow(key_label, self.key_plain_text_edit)
        form_layout.addRow(self.iv_label, self.iv_plain_text_edit)
        form_layout.addRow(data_label, data_layout)
        form_layout.addRow(output_label, self.output_text_browser)
        form_layout.addRow(mode_label, self.mode_combo_box)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)

        self.output_text_browser.setReadOnly(True)

        self.setLayout(main_layout)

        self.update_mode()
        self.update_placeholder_text()
        self.mode_combo_box.currentIndexChanged.connect(self.update_mode)
        self.key_plain_text_edit.textChanged.connect(self.update_placeholder_text)
        self.iv_plain_text_edit.textChanged.connect(self.update_placeholder_text)

    def update_mode(self):
        selected_mode = self.mode_combo_box.currentText()
        if selected_mode == "ECB":
            self.iv_label.hide()
            self.iv_plain_text_edit.hide()
        else:
            self.iv_label.show()
            self.iv_plain_text_edit.show()

        # 设置 key_plain_text_edit 的默认值和提示文本
        if not self.key_plain_text_edit.toPlainText():
            self.key_plain_text_edit.setPlaceholderText("输入长度为16的字符串")

        # 设置 iv_plain_text_edit 的默认值和提示文本
        if not self.iv_plain_text_edit.toPlainText():
            self.iv_plain_text_edit.setPlaceholderText("输入长度为16的字符串")

        # 设置 data_plain_text_edit 的提示文本
        if selected_mode in ["CFB", "OFB", "CTR"]:
            self.data_plain_text_edit.setPlaceholderText("加密时输入长度为16的倍数的字符串")
        else:
            self.data_plain_text_edit.setPlaceholderText("加密时输入任意长度的字符串")

    def update_placeholder_text(self):
        # 设置 key_plain_text_edit 的默认值和提示文本
        if not self.key_plain_text_edit.toPlainText():
            self.key_plain_text_edit.setPlaceholderText("输入长度为16的字符串")

        # 设置 iv_plain_text_edit 的默认值和提示文本
        if not self.iv_plain_text_edit.toPlainText():
            self.iv_plain_text_edit.setPlaceholderText("输入长度为16的字符串")

        selected_mode = self.mode_combo_box.currentText()
        # 设置 data_plain_text_edit 的提示文本
        if selected_mode in ["CFB", "OFB", "CTR"]:
            self.data_plain_text_edit.setPlaceholderText("加密时输入长度为16的倍数的字符串")
        else:
            self.data_plain_text_edit.setPlaceholderText("加密时输入任意长度的字符串")

    def echo(self) -> None:

        def encrypt():
            key = self.key_plain_text_edit.toPlainText()
            iv = self.iv_plain_text_edit.toPlainText()
            data = self.data_plain_text_edit.toPlainText()
            mode = self.mode_combo_box.currentText()
            selected_mode = self.mode_combo_box.currentText()

            if len(key) != 16 or len(iv) != 16:
                QMessageBox.warning(self, "无效输入", "密钥和初始化向量必须为16个字符长。")
                return False

            if selected_mode in ["CFB", "OFB", "CTR"] and len(data) % 16 != 0:
                QMessageBox.warning(self, "无效输入", "对于所选的加密模式，数据长度必须是16的倍数。")

            aes = AESCipher(key, mode, iv)
            output = aes.encrypt(data)
            output_text = ''.join([hex(num)[2:].zfill(2) for num in output])
            self.output_text_browser.setText(output_text)

        def decrypt():
            key = self.key_plain_text_edit.toPlainText()
            iv = self.iv_plain_text_edit.toPlainText()
            data = self.data_plain_text_edit.toPlainText()
            mode = self.mode_combo_box.currentText()

            aes = AESCipher(key, mode, iv)
            try:
                output_text = aes.decrypt(data)
            except Exception as e:
                QMessageBox.warning(self, "解密错误", "解密过程中发生错误，请确保所解密数据为正常加密所得到的数据。")
                return
            self.output_text_browser.setText(output_text)


        self.encrypt_button.clicked.connect(encrypt)
        self.decrypt_button.clicked.connect(decrypt)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyWidget()
    window.show()
    sys.exit(app.exec())
