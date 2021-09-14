# This file is used to augment the test configuration

import os

def pytest_addoption(parser):
    parser.addoption("--volatility", action="store", default=None,
        required=True,
        help="path to the volatility script")

    parser.addoption("--python", action="store", default="python3",
        help="The name of the interpreter to use when running the volatility script")

    parser.addoption("--image", action="append", default=[],
        help="path to an image to test")

    parser.addoption("--image-dir", action="append", default=[],
        help="path to a directory containing images to test")

def pytest_generate_tests(metafunc):
    """Parameterize tests based on image names"""

    images = metafunc.config.getoption('image')
    for d in metafunc.config.getoption('image_dir'):
        images = images + [os.path.join(d, x) for x in os.listdir(d)]

    # tests with "image" parameter are run against images
    if 'image' in metafunc.fixturenames:
        metafunc.parametrize("image",
            images,
            ids=[os.path.basename(image) for image in images])
