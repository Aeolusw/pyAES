import sys
from PySide6 import QtWidgets

from AES.aes_encrypt import AES


class MyWidget(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle("AES 加密")
        self.setFixedSize(400, 200)
        self.setup_ui()
        self.echo()

    def setup_ui(self) -> None:
        key_label = QtWidgets.QLabel("Key:")
        data_label = QtWidgets.QLabel("Data:")
        output_label = QtWidgets.QLabel("Output:")

        self.key_edit = QtWidgets.QLineEdit()
        self.data_edit = QtWidgets.QLineEdit()
        self.output_edit = QtWidgets.QLineEdit()

        self.button = QtWidgets.QPushButton("Encrypt")

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow(key_label, self.key_edit)
        form_layout.addRow(data_label, self.data_edit)
        form_layout.addRow(output_label, self.output_edit)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.button)

        self.output_edit.setReadOnly(True)

        self.setLayout(main_layout)


    def echo(self) -> None:
        self.key_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        self.data_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)

        def encrypt():
            key = self.key_edit.text()
            data = self.data_edit.text()

            aes = AES(key, data)
            output = aes.encrypt()

            output_text = ' '.join([hex(num)[2:].zfill(2) for num in output])
            self.output_edit.setText(output_text)

        self.button.clicked.connect(encrypt)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyWidget()
    window.show()
    sys.exit(app.exec())
