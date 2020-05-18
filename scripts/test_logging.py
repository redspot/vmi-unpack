#!/usr/bin/env python

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

log_format = '%(asctime)s %(filename)s: %(message)s'
# logging.basicConfig(format=log_format, datefmt='%Y-%m-%d %H:%M:%S')

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(
        format='%(asctime)s %(levelname)s:%(name)s %(message)s',
        )


def main():
    logger.info("information message")
    logger.debug("debug message")


if __name__ == '__main__':
    main()
