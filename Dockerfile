FROM php:7.4-cli
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/ShashwatSen/CatEye && cp -r CatEye /usr/src/cateye
WORKDIR /usr/src/cateye
CMD [ "php", "./rhawk.php", "<<<","$'fix'" ]
CMD [ "php", "./rhawk.php", "<<<","$'update'" ]
CMD [ "php", "./rhawk.php" ]
