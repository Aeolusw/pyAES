import sys
from PySide6 import QtWidgets

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

        self.mode_combo_box.addItems(["ECB", "CBC", "CFB", "OFB"])
        self.encrypt_button = QtWidgets.QPushButton("Encrypt")
        self.decrypt_button = QtWidgets.QPushButton("Decrypt")

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

        self.update_ui()
        self.mode_combo_box.currentIndexChanged.connect(self.update_ui)

    def update_ui(self):
        selected_mode = self.mode_combo_box.currentText()
        if selected_mode == "ECB":
            self.iv_label.hide()
            self.iv_plain_text_edit.hide()
        else:
            self.iv_label.show()
            self.iv_plain_text_edit.show()

    def echo(self) -> None:

        def encrypt():
            key = self.key_plain_text_edit.toPlainText()
            iv = self.iv_plain_text_edit.toPlainText()
            data = self.data_plain_text_edit.toPlainText()
            mode = self.mode_combo_box.currentText()

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
            output_text = aes.decrypt(data)
            self.output_text_browser.setText(output_text)

        self.encrypt_button.clicked.connect(encrypt)
        self.decrypt_button.clicked.connect(decrypt)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyWidget()
    window.show()
    sys.exit(app.exec())
