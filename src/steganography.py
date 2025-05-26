"""
Core steganography algorithms for hiding and extracting data in images.
"""

from PIL import Image


class SteganographyEngine:
    """Handles the core steganography operations using LSB (Least Significant Bit) method."""

    def __init__(self):
        self.TERMINATOR = '1111111111111110'  # 16-bit terminator pattern

    def calculate_capacity(self, image):
        """
        Calculate the maximum message capacity for an image.

        Args:
            image (PIL.Image): The image to analyze

        Returns:
            int: Maximum bytes that can be hidden in the image
        """
        width, height = image.size
        total_pixels = width * height

        # Determine bits per pixel based on color mode
        if image.mode == 'RGB':
            bits_per_pixel = 3
        elif image.mode == 'RGBA':
            bits_per_pixel = 4
        else:
            bits_per_pixel = 1

        # Reserve 32 bits for length header and 16 bits for terminator
        total_bytes = (total_pixels * bits_per_pixel) // 8 - 4 - 2
        return max(0, total_bytes)

    def get_image_info(self, image):
        """
        Get detailed information about an image.

        Args:
            image (PIL.Image): The image to analyze

        Returns:
            dict: Image information including dimensions, mode, and capacity
        """
        width, height = image.size
        capacity = self.calculate_capacity(image)

        return {
            'width': width,
            'height': height,
            'mode': image.mode,
            'total_pixels': width * height,
            'capacity_bytes': capacity,
            'capacity_kb': capacity / 1024
        }

    def text_to_binary(self, text):
        """
        Convert text to binary format with length header and terminator.

        Args:
            text (str): Text to convert

        Returns:
            str: Binary representation with 32-bit length header and terminator
        """
        text_bytes = text.encode('utf-8')
        length = len(text_bytes)

        # 32-bit length header + data + terminator
        length_binary = format(length, '032b')
        text_binary = ''.join(format(byte, '08b') for byte in text_bytes)

        return length_binary + text_binary + self.TERMINATOR

    def bytes_to_binary(self, data):
        """
        Convert bytes to binary format with length header and terminator.

        Args:
            data (bytes): Data to convert

        Returns:
            str: Binary representation with 32-bit length header and terminator
        """
        length = len(data)
        length_binary = format(length, '032b')
        data_binary = ''.join(format(byte, '08b') for byte in data)

        return length_binary + data_binary + self.TERMINATOR

    def embed_data_lsb(self, image, binary_data):
        """
        Embed binary data into image using LSB steganography.

        Args:
            image (PIL.Image): Image to embed data into
            binary_data (str): Binary string to embed

        Returns:
            PIL.Image: Modified image with embedded data

        Raises:
            ValueError: If data is too large for the image
        """
        # Ensure image is in compatible format
        if image.mode not in ['RGB', 'RGBA']:
            image = image.convert('RGB')

        # Check capacity
        capacity = self.calculate_capacity(image)
        required_bytes = len(binary_data) // 8

        if required_bytes > capacity:
            raise ValueError(f"Data too large. Required: {required_bytes} bytes, Available: {capacity} bytes")

        # pixel data
        pixels = list(image.getdata())
        message_index = 0

        # embed data into LSBs
        for i in range(len(pixels)):
            if message_index >= len(binary_data):
                break

            pixel = list(pixels[i])

            # modification of color channels
            for j in range(len(pixel)):
                if message_index < len(binary_data):
                    pixel[j] = (pixel[j] & 0xFE) | int(binary_data[message_index])
                    message_index += 1

            pixels[i] = tuple(pixel)

        # new image with modified pixels
        result_image = image.copy()
        result_image.putdata(pixels)

        return result_image

    def extract_data_lsb(self, image):
        """
        Extract hidden data from image using LSB steganography.

        Args:
            image (PIL.Image): Image to extract data from

        Returns:
            bytes: Extracted data, or None if no valid data found
        """
        if image.mode not in ['RGB', 'RGBA']:
            image = image.convert('RGB')

        pixels = list(image.getdata())
        binary_data = ""

        # extraction of LSBs
        for pixel in pixels:
            for channel in pixel:
                binary_data += str(channel & 1)

        # 32 bits for length header
        if len(binary_data) < 32:
            return None

        # read first 32 bits
        try:
            length_binary = binary_data[:32]
            data_length = int(length_binary, 2)
        except ValueError:
            return None

        if data_length <= 0 or data_length > (len(binary_data) - 32) // 8:
            return None

        # data portion
        data_start = 32
        data_end = data_start + (data_length * 8)

        if data_end > len(binary_data):
            return None

        data_binary = binary_data[data_start:data_end]

        # binary to bytes
        try:
            data_bytes = []
            for i in range(0, len(data_binary), 8):
                byte_str = data_binary[i:i + 8]
                if len(byte_str) == 8:
                    data_bytes.append(int(byte_str, 2))

            return bytes(data_bytes)

        except (ValueError, OverflowError):
            return None

    def hide_text(self, image, text):
        """
        Hide text message in image.

        Args:
            image (PIL.Image): Image to hide text in
            text (str): Text to hide

        Returns:
            PIL.Image: Image with hidden text
        """
        binary_data = self.text_to_binary(text)
        return self.embed_data_lsb(image, binary_data)

    def extract_text(self, image):
        """
        Extract text message from image.

        Args:
            image (PIL.Image): Image to extract text from

        Returns:
            str: Extracted text, or None if no valid text found
        """
        data = self.extract_data_lsb(image)
        if data is None:
            return None

        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return None

    def hide_bytes(self, image, data):
        """
        Hide raw bytes in image.

        Args:
            image (PIL.Image): Image to hide data in
            data (bytes): Data to hide

        Returns:
            PIL.Image: Image with hidden data
        """
        binary_data = self.bytes_to_binary(data)
        return self.embed_data_lsb(image, binary_data)

    def validate_image(self, image_path):
        """
        Validate if an image file is suitable for steganography.

        Args:
            image_path (str): Path to image file

        Returns:
            tuple: (bool, str) - (is_valid, error_message)
        """
        try:
            image = Image.open(image_path)

            # format
            if image.format not in ['PNG', 'BMP']:
                return False, f"Unsupported format: {image.format}. Use PNG or BMP files."

            # size
            width, height = image.size
            if width * height < 100:  # Minimum 100 pixels
                return False, "Image too small for steganography."

            # capacity
            capacity = self.calculate_capacity(image)
            if capacity < 1:
                return False, "Image has insufficient capacity for hiding data."

            return True, "Image is suitable for steganography."

        except Exception as e:
            return False, f"Error reading image: {str(e)}"