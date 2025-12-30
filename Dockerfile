FROM php:7.4-cli
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/ShashwatSen/CatEye && cp -r CatEye /usr/src/cateye
WORKDIR /usr/src/cateye
CMD [ "php", "./cateye.php", "<<<","$'fix'" ]
CMD [ "php", "./cateye.php", "<<<","$'update'" ]
CMD [ "php", "./cateye.php" ]
