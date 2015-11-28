from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from time import sleep


driver = webdriver.Firefox()
driver.get("http://www.stackoverflow.com")
element = driver.find_element_by_xpath("//div[@id='tabs']/a[@data-value='hot']")
element.send_keys(Keys.RETURN)
driver.close()