from flask import Flask, request, send_file, render_template, redirect, url_for, flash, make_response
from PIL import Image, ImageFilter, ImageFont, ImageDraw, ImageOps, ImageEnhance
from werkzeug.utils import secure_filename
import os
import logging
import datetime
import zipfile
import uuid

app = Flask(__name__)

# Use an environment variable for the secret key in production:
# export SECRET_KEY='your-secure-random-key'
app.secret_key = os.environ.get('SECRET_KEY', 'replace-with-your-secret-key')

# Configure folders
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'output')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def unique_filename(prefix='image', ext='png'):
    """Generate a unique filename using UUID."""
    return f"{prefix}_{uuid.uuid4().hex}.{ext}"

def apply_filter_to_image(input_path, filter_type):
    """
    Apply different filters to the image. Returns output_path if successful, else None.
    """
    output_path = None
    try:
        with Image.open(input_path) as img:
            img = img.convert('RGBA')

            filter_map = {
                'gaussian_blur': ImageFilter.GaussianBlur(5),
                'blur': ImageFilter.BLUR,
                'contour': ImageFilter.CONTOUR,
                'detail': ImageFilter.DETAIL,
                'edge_enhance': ImageFilter.EDGE_ENHANCE,
                'edge_enhance_more': ImageFilter.EDGE_ENHANCE_MORE,
                'emboss': ImageFilter.EMBOSS,
                'find_edges': ImageFilter.FIND_EDGES,
                'sharpen': ImageFilter.SHARPEN,
                'smooth': ImageFilter.SMOOTH,
                'smooth_more': ImageFilter.SMOOTH_MORE
            }

            # Apply filter based on filter_type
            if filter_type == 'invert':
                img = img.convert('RGB')
                img = ImageOps.invert(img).convert('RGBA')
            elif filter_type == 'posterize':
                img = img.convert('RGB')
                img = ImageOps.posterize(img, bits=4).convert('RGBA')
            elif filter_type == 'solarize':
                img = img.convert('RGB')
                img = ImageOps.solarize(img, threshold=128).convert('RGBA')
            elif filter_type == 'autocontrast':
                img = img.convert('RGB')
                img = ImageOps.autocontrast(img).convert('RGBA')
            elif filter_type == 'equalize':
                img = img.convert('RGB')
                img = ImageOps.equalize(img).convert('RGBA')
            elif filter_type == 'grayscale':
                img = img.convert('L').convert('RGBA')
            elif filter_type == 'colorize':
                gray_img = img.convert('L')
                img = ImageOps.colorize(gray_img, black="blue", white="yellow").convert('RGBA')
            elif filter_type in filter_map:
                img = img.filter(filter_map[filter_type])
            elif filter_type.startswith('brightness_'):
                enhancer = ImageEnhance.Brightness(img)
                factor = 1.5 if filter_type == 'brightness_up' else 0.5
                img = enhancer.enhance(factor)
            elif filter_type.startswith('contrast_'):
                enhancer = ImageEnhance.Contrast(img)
                factor = 1.5 if filter_type == 'contrast_up' else 0.5
                img = enhancer.enhance(factor)
            elif filter_type.startswith('color_'):
                enhancer = ImageEnhance.Color(img)
                factor = 1.5 if filter_type == 'color_up' else 0.5
                img = enhancer.enhance(factor)
            elif filter_type.startswith('sharpen_enhance'):
                enhancer = ImageEnhance.Sharpness(img)
                factor = 2.0 if filter_type == 'sharpen_enhance_up' else 0.5
                img = enhancer.enhance(factor)
            else:
                logger.warning(f"Filter type '{filter_type}' not recognized. Defaulting to grayscale.")
                img = img.convert('L').convert('RGBA')

            output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('filtered'))
            img.save(output_path, format='PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error applying filter '{filter_type}': {e}")
        return None

def convert_image(input_path, size=(1024, 1024)):
    try:
        with Image.open(input_path) as img:
            img = img.resize(size, Image.LANCZOS)
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('converted'))
            img.save(output_path, format='PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error converting image: {e}")
        return None

def generate_ios_app_icons(input_path):
    sizes = [
        (20, 1), (20, 2), (20, 3),
        (29, 1), (29, 2), (29, 3),
        (40, 1), (40, 2), (40, 3),
        (60, 2), (60, 3),
        (76, 1), (76, 2),
        (83.5, 2),
        (1024, 1)
    ]

    icon_paths = []
    try:
        with Image.open(input_path) as img:
            for base_size, scale in sizes:
                output_size = (int(base_size * scale), int(base_size * scale))
                icon_img = img.resize(output_size, Image.LANCZOS)
                filename = f"icon_{base_size}x{base_size}@{scale}x.png".replace('.5', 'p5')
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
                icon_img.save(output_path, format='PNG')
                icon_paths.append(output_path)
    except Exception as e:
        logger.error(f"Error generating iOS app icons: {e}")
        return None
    return icon_paths

def create_homescreen_mockup(icon_path):
    mockup_path = os.path.join('static', 'mockups', 'homescreen_mockup.png')
    if not os.path.exists(mockup_path):
        logger.error("Homescreen mockup base image not found.")
        return None

    try:
        with Image.open(mockup_path) as bg:
            with Image.open(icon_path) as icon:
                icon = icon.resize((180, 180), Image.LANCZOS)
                bg.paste(icon, (100, 300), icon)
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('homescreen'))
                bg.save(output_path, format='PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error creating homescreen mockup: {e}")
        return None

def overlay_frame(input_path):
    frame_path = os.path.join('static', 'frames', 'iphone_frame.png')
    if not os.path.exists(frame_path):
        logger.error("Frame image not found.")
        return None

    try:
        with Image.open(frame_path) as frame:
            with Image.open(input_path) as img:
                display_x, display_y = 200, 300
                display_w, display_h = 600, 1300
                screenshot = img.resize((display_w, display_h), Image.LANCZOS)
                frame.paste(screenshot, (display_x, display_y))
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('framed'))
                frame.save(output_path, 'PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error overlaying frame: {e}")
        return None

def convert_color_profile(input_path):
    try:
        with Image.open(input_path) as img:
            img = img.convert('RGB')
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('srgb'))
            img.save(output_path, format='PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error converting color profile: {e}")
        return None

def generate_launch_screen(input_path):
    bg_path = os.path.join('static', 'backgrounds', 'launch_background.png')
    if not os.path.exists(bg_path):
        logger.error("Launch background not found.")
        return None

    try:
        with Image.open(bg_path) as bg:
            with Image.open(input_path) as fg:
                bg_w, bg_h = bg.size
                fg = fg.resize((int(bg_w*0.5), int(bg_h*0.5)), Image.LANCZOS)
                fg_w, fg_h = fg.size
                offset = ((bg_w - fg_w)//2, (bg_h - fg_h)//2)
                bg.paste(fg, offset, fg if fg.mode == 'RGBA' else None)
                output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('launchscreen'))
                bg.save(output_path, 'PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error generating launch screen: {e}")
        return None

def generate_typography_preview(text="Hello, iOS!", font_size=72):
    font_path = os.path.join('static', 'fonts', 'SanFrancisco.ttf')
    if not os.path.exists(font_path):
        logger.error("Font file not found for typography preview.")
        return None

    try:
        img = Image.new('RGBA', (1200, 200), (255,255,255,0))
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype(font_path, font_size)
        text_w, text_h = draw.textsize(text, font=font)
        draw.text(((1200-text_w)//2, (200-text_h)//2), text, font=font, fill=(0,0,0,255))
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], unique_filename('typography'))
        img.save(output_path, 'PNG')
        return output_path
    except Exception as e:
        logger.error(f"Error generating typography preview: {e}")
        return None

def zip_files(file_paths, zip_name='assets.zip'):
    zip_path = os.path.join(app.config['OUTPUT_FOLDER'], zip_name)
    try:
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for fp in file_paths:
                zf.write(fp, os.path.basename(fp))
        return zip_path
    except Exception as e:
        logger.error(f"Error creating zip file: {e}")
        return None

def send_no_cache_file(path, **kwargs):
    """
    Wrapper for send_file that adds no-cache headers.
    """
    resp = make_response(send_file(path, **kwargs))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/xcode/', methods=['GET'])
def index():
    # Main page (showing forms/tabs) 
    return render_template('index.html', current_year=datetime.datetime.now().year)

@app.route('/xcode/instructions', methods=['GET'])
def instructions():
    return render_template('instructions.html')

@app.route('/xcode/convert', methods=['GET', 'POST'])
def upload_image():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part found in the request.")
            return redirect(url_for('index'))

        file = request.files['file']
        if file.filename == '':
            flash("No file selected. Please choose an image.")
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        if filename:
            input_filename = unique_filename('uploaded')
            input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
            file.save(input_image_path)

            output_path = convert_image(input_image_path)
            if output_path:
                return redirect(url_for('preview_image', filename=os.path.basename(output_path)))
            else:
                flash("An error occurred during conversion. Please try again with a valid image.")
                return redirect(url_for('index'))
        else:
            flash("Invalid filename.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.route('/xcode/preview/<filename>')
def preview_image(filename):
    output_image_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if not os.path.exists(output_image_path):
        flash("The requested file does not exist.")
        return redirect(url_for('index'))
    return render_template('preview.html', filename=filename)

@app.route('/xcode/download/<filename>')
def download_image(filename):
    output_image_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if os.path.exists(output_image_path):
        return send_no_cache_file(output_image_path, mimetype='image/png', as_attachment=True)
    else:
        flash("The requested file does not exist.")
        return redirect(url_for('index'))

@app.route('/xcode/generate_icon_set', methods=['POST'])
def generate_icon_set():
    if 'file' not in request.files:
        flash("No file uploaded for icon set generation.")
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected for icon set generation.")
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    if filename:
        input_filename = unique_filename('uploaded')
        input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        file.save(input_image_path)
        icon_paths = generate_ios_app_icons(input_image_path)

        if not icon_paths:
            flash("Failed to generate icon set.")
            return redirect(url_for('index'))

        zip_path = zip_files(icon_paths, 'ios_app_icons.zip')
        if zip_path:
            return render_template('icon_set_generated.html', zip_path=os.path.basename(zip_path))
        else:
            flash("Error creating zip file.")
            return redirect(url_for('index'))
    else:
        flash("Invalid filename.")
        return redirect(url_for('index'))

@app.route('/xcode/download_assets/<filename>')
def download_assets(filename):
    assets_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if os.path.exists(assets_path):
        return send_no_cache_file(assets_path, as_attachment=True)
    else:
        flash("The requested asset file does not exist.")
        return redirect(url_for('index'))

@app.route('/xcode/filters', methods=['GET', 'POST'])
def filters():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file selected.")
            return redirect(url_for('index'))

        file = request.files['file']
        filter_pipeline = request.form.get('filter_pipeline', '')
        filters_to_apply = [f.strip() for f in filter_pipeline.split(',') if f.strip()]

        if file.filename == '':
            flash("No file selected.")
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        if filename:
            input_filename = unique_filename('uploaded')
            input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
            file.save(input_image_path)

            # Apply each filter in sequence
            current_path = input_image_path
            for f_type in filters_to_apply:
                filtered_path = apply_filter_to_image(current_path, f_type)
                if filtered_path is None:
                    flash(f"Error applying filter '{f_type}'. Please try another image or filter.")
                    return redirect(url_for('index'))
                current_path = filtered_path

            # Return the final filtered image as a download
            return send_no_cache_file(current_path, as_attachment=True, mimetype='image/png')
        else:
            flash("Invalid filename.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.route('/xcode/homescreen_mockup/<filename>')
def homescreen_mockup(filename):
    output_image_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if not os.path.exists(output_image_path):
        flash("The requested file does not exist.")
        return redirect(url_for('index'))

    mockup_path = create_homescreen_mockup(output_image_path)
    if mockup_path:
        return render_template('mockup_preview.html', mockup_filename=os.path.basename(mockup_path))
    else:
        flash("Error creating homescreen mockup.")
        return redirect(url_for('index'))

@app.route('/xcode/frame_screenshot', methods=['POST'])
def frame_screenshot():
    if 'file' not in request.files:
        flash("No file selected.")
        return redirect(url_for('index'))
    file = request.files['file']
    filename = secure_filename(file.filename)
    if filename:
        input_filename = unique_filename('uploaded')
        input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        file.save(input_image_path)
        framed_path = overlay_frame(input_image_path)
        if framed_path:
            return render_template('frame_preview.html', frame_filename=os.path.basename(framed_path))
        else:
            flash("Error creating framed screenshot.")
            return redirect(url_for('index'))
    else:
        flash("Invalid filename.")
        return redirect(url_for('index'))

@app.route('/xcode/convert_color_profile', methods=['POST'])
def convert_profile():
    if 'file' not in request.files:
        flash("No file selected.")
        return redirect(url_for('index'))
    file = request.files['file']
    filename = secure_filename(file.filename)
    if filename:
        input_filename = unique_filename('uploaded')
        input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        file.save(input_image_path)
        srgb_path = convert_color_profile(input_image_path)
        if srgb_path:
            return send_no_cache_file(srgb_path, as_attachment=True, mimetype='image/png')
        else:
            flash("Error converting color profile.")
            return redirect(url_for('index'))
    else:
        flash("Invalid filename.")
        return redirect(url_for('index'))

@app.route('/xcode/generate_launch_screen', methods=['POST'])
def create_launch_screen():
    if 'file' not in request.files:
        flash("No file selected.")
        return redirect(url_for('index'))
    file = request.files['file']
    filename = secure_filename(file.filename)
    if filename:
        input_filename = unique_filename('uploaded')
        input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        file.save(input_image_path)
        launch_path = generate_launch_screen(input_image_path)
        if launch_path:
            return render_template('launch_screen_generated.html', launch_filename=os.path.basename(launch_path))
        else:
            flash("Error generating launch screen.")
            return redirect(url_for('index'))
    else:
        flash("Invalid filename.")
        return redirect(url_for('index'))

@app.route('/xcode/typography_preview', methods=['GET', 'POST'])
def typography_preview():
    if request.method == 'POST':
        text = request.form.get('text', 'Hello, iOS!')
        font_size = int(request.form.get('font_size', 72))
        preview_path = generate_typography_preview(text=text, font_size=font_size)
        if preview_path:
            return render_template('typography_preview.html', preview_filename=os.path.basename(preview_path))
        else:
            flash("Error generating typography preview.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

if __name__ == '__main__':
    # In production, run with a proper WSGI server.
    app.run(host='0.0.0.0', port=699, debug=False)