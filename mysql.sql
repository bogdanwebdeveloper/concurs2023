CREATE TABLE `users` (
  `usersId` int(11) NOT NULL,
  `usersUsername` varchar(128) NOT NULL,
  `usersEmail` varchar(128) NOT NULL,
  `usersPassword` varchar(128) NOT NULL,
  `usersRealname` varchar(128) NOT NULL,
  `usersAdmin` int(11) NULL,
  `usersPhone` int(12) NOT NULL,
  `registerDate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `vkey` varchar(128) NOT NULL DEFAULT '0',
  `verified` int(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


INSERT INTO `users` (`usersId`, `usersUsername`, `usersEmail`, `usersPassword`, `usersRealname`, `usersAdmin`, `usersPhone`, `registerDate`, `vkey`, `verified`) VALUES
(1, 'admin', 'test@localhost.app', '$2y$10$9m6lq8ev0CZIGo66fWvLYubizyXxFspbxQ8CCtyZX/spXYIG24jKu', 'Admin', 1, 0, '2022-07-11 18:53:46', '0', '0');

ALTER TABLE `users`
  ADD PRIMARY KEY (`usersId`);

ALTER TABLE `users`
  MODIFY `usersId` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;
